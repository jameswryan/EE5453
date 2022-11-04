#!/usr/bin/env python3

import json
import asyncio
import binascii
import sys
import os

from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Union, Tuple, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


async def read_all(reader: StreamReader) -> bytes:
    """
      Read from stream until read() returns 0
    """
    buf_size = 1024
    buf = bytearray(await reader.read(buf_size))
    byts_recvd = len(buf)

    while byts_recvd == buf_size:
        _buf = await reader.read(buf_size)
        byts_recvd = len(_buf)
        buf.extend(_buf)
    return buf


@dataclass
class FileWithName:
    """"
        Struct to hold file + name
    """
    name: str
    contents: bytes


RequestType = Union[str, FileWithName]


def deser_request_from_json(js: bytes) -> RequestType:
    """
        Deserializes a request from JSON in js.
        If the request was a Get with a filename, returns the requested
        filename
        If the request was a Put with filename + contents, returns a
        FileWithName with appropriate name + contents
        If the request wasnt Put or Get, raises ValueError
        If decoding from JSON fails, raises JSONDecodeError
    """

    decoded = json.loads(js)

    if decoded.get('Put') is not None:
        return FileWithName(name=decoded['Put']['name'],
                            contents=decoded['Put']['contents'])
    elif decoded.get('Get') is not None:
        return str(decoded['Get'])
    else:
        raise ValueError


def handle_put_request(request: FileWithName):
    fname = os.path.basename(request.name)
    if fname == '':
        print(f"Couldn't find a filename in {fname}", file=sys.stderr)
        return

    fcontents = request.contents

    with open(fname, 'wb') as file:
        file.write(bytearray(fcontents))


def handle_get_request(writer: StreamWriter, request: str, keys: dict[str,
                                                                      Any]):
    # Retrieve the file
    fname = os.path.basename(request)
    if fname == '':
        print(f"Couldn't find a filename in {fname}", file=sys.stderr)
        return

    with open(fname, 'rb') as file:
        contents = file.read()
        # Encrypt
        network_bytes = encrypt_to_from(contents, keys["client_enck"],
                                        keys["server_sigk"])
        # Send payload
        writer.write(network_bytes)


def unpack_sig(payload: bytes) -> Tuple[bytes, bytes]:
    if len(payload) < 512:
        raise TypeError("Payload too short!")
    return (payload[:512], payload[512:])


def lchunks(l, n):
    """
      Split `l` into lists of size `size`
      If len(l) % size !=0, last list will be shorter
    """
    chnks = []
    for i in range(0, len(l), n):
        chnks.append(l[i:min(i+n, len(l))])
    return chnks
    
from typing import Iterable
def flatten(llist: Iterable[Iterable]):
    return [it for l in llist for it in l]
        

def decrypt_from_to(payload, client_vrfk, server_deck):
    (sig, ct) = unpack_sig(payload)
    # Verify signature
    cvn = client_vrfk.public_numbers().n
    to_check = bytearray(
        cvn.to_bytes(length=(cvn.bit_length() + 7) // 8, byteorder='big'))
    sdn = server_deck.public_key().public_numbers().n
    to_check.extend(
        sdn.to_bytes(length=(sdn.bit_length() + 7) // 8, byteorder='big'))
    to_check.extend(ct)

    client_vrfk.verify(
        bytes(sig), to_check,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    # Verified signature, can decrypt & use plaintext
    pt = bytes(flatten(map(lambda blk: server_deck.decrypt(
        bytes(blk),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)), lchunks(ct, 512))))
    return pt


def encrypt_to_from(pt, client_enck, server_sigk) -> bytes:
    # encrypt
    ct = bytes(
            flatten(
                map(lambda blk: client_enck.encrypt(bytes(blk),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)),
                lchunks(pt, 128)
                )
            )
        )

    # Build the thing to sign
    ssn = server_sigk.public_key().public_numbers().n
    to_sign = bytearray(ssn.to_bytes((ssn.bit_length() + 7) // 8, byteorder='big'))
    cen = client_enck.public_numbers().n
    to_sign.extend(cen.to_bytes((cen.bit_length() + 7) // 8, byteorder='big'))
    to_sign.extend(ct)

    # sign it
    sig = server_sigk.sign(
        bytes(to_sign),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print(binascii.hexlify(sig))

    payload = bytearray(sig)
    payload.extend(ct)

    return payload


def read_keys() -> dict[str, Any]:
    client_enck_path = "client_enck.pem"
    client_vrfk_path = "client_vrfk.pem"
    server_deck_path = "server_deck.pem"
    server_sigk_path = "server_sigk.pem"

    with open(client_enck_path, "rb") as file:
        client_enck = load_pem_public_key(file.read(), )

    assert isinstance(client_enck, rsa.RSAPublicKey)

    with open(client_vrfk_path, "rb") as file:
        client_vrfk = load_pem_public_key(file.read(), )

    assert isinstance(client_vrfk, rsa.RSAPublicKey)

    with open(server_deck_path, "rb") as file:
        server_deck = load_pem_private_key(
            file.read(),
            None,
        )

    assert isinstance(server_deck, rsa.RSAPrivateKey)

    with open(server_sigk_path, "rb") as file:
        server_sigk = load_pem_private_key(
            file.read(),
            None,
        )

    assert isinstance(server_sigk, rsa.RSAPrivateKey)

    return {
        "client_enck": client_enck,
        "client_vrfk": client_vrfk,
        "server_deck": server_deck,
        "server_sigk": server_sigk
    }


async def handle_connection(reader: StreamReader, writer: StreamWriter):

    keys = read_keys()
    recvd = await read_all(reader)

    # Need to decrypt recvd w/DH secret to get plaintext
    plaintext = decrypt_from_to(recvd, keys["client_vrfk"],
                                    keys["server_deck"])

    # (try) to decode line from json
    try:
        request = deser_request_from_json(plaintext)
        print(request)
    except JSONDecodeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        exit(1)

    # Need to figure out how to respond/respond appropriately here
    if type(request) == FileWithName:
        # Put request
        handle_put_request(request)
    elif type(request) == str:
        # Get request
        handle_get_request(writer, request, keys)
    else:
        print("Bad request!", file=sys.stderr)

    writer.close()


async def main():
    server = await asyncio.start_server(
        handle_connection,
        "localhost",
        0xBEEF,
    )

    addrs = ', '.join(str(soc.getsockname()) for soc in server.sockets)

    print(f"serving on {addrs}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
    exit(0)
