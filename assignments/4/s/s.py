#!/usr/bin/env python3

import json
import asyncio
import binascii
import sys
import os

from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Union, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key


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


def handle_get_request(writer: StreamWriter, request: str, key: bytes):
    # Retrieve the file
    fname = os.path.basename(request)
    if fname == '':
        print(f"Couldn't find a filename in {fname}", file=sys.stderr)
        return

    with open(fname, 'rb') as file:
        contents = file.read()
        # Encrypt
        network_bytes = encrypt(contents, key)
        # Send payload
        writer.write(network_bytes)


def key_unwrap(key: bytes) -> Tuple[bytes, bytes]:
    if len(key) != 64:
        raise TypeError("Invalid Key Length!")

    return (key[:32], key[32:])


def decrypt(payload, key):
    # Decrypt AES256CBC/CBCMAC
    (ekey, mkey) = key_unwrap(key)

    iv = payload[:16]
    tag = payload[-16:]

    ct = payload[16:-16]

    mac_cipher = Cipher(AES256(mkey), CBC(iv)).encryptor()

    tag_cmptd = (mac_cipher.update(ct) + mac_cipher.finalize())[-16:]

    if tag_cmptd != tag:
        raise ValueError("Bad Tag!")

    enc_cipher = Cipher(AES256(ekey), CBC(iv)).decryptor()

    pt = enc_cipher.update(ct) + enc_cipher.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    pt = (unpadder.update(pt) + unpadder.finalize())

    return pt


def encrypt(pt, key) -> bytes:
    # Encrypt AES256CBC/CBCMAC
    (ekey, mkey) = key_unwrap(key)

    padder = padding.PKCS7(128).padder()
    padded = (padder.update(pt) + padder.finalize())

    iv = os.getrandom(16)

    enc_cipher = Cipher(AES256(ekey), CBC(iv)).encryptor()
    ct = enc_cipher.update(padded) + enc_cipher.finalize()

    padder = padding.PKCS7(128).padder()
    padded = (padder.update(ct) + padder.finalize())
    mac_cipher = Cipher(AES256(mkey), CBC(iv)).encryptor()

    tag = (mac_cipher.update(padded) + mac_cipher.finalize())[-16:]

    print(f"iv : {binascii.hexlify(iv)!r}\ntag: {binascii.hexlify(tag)!r}")

    payload = bytearray(iv)
    payload.extend(ct)
    payload.extend(tag)

    return payload


async def get_shared_secret(reader: StreamReader, writer: StreamWriter):
    # FFDH parameters
    ffdh_g = 2
    ffdh_p = int.from_bytes(binascii.unhexlify('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF'), byteorder='big')

    ffdh_param_numbers = dh.DHParameterNumbers(ffdh_p, ffdh_g)
    ffdh_params = ffdh_param_numbers.parameters()
    ffdh = ffdh_params.generate_private_key()

    # Read clients public key
    client_pk_bytes = await read_all(reader)

    client_pk = load_pem_public_key(client_pk_bytes)

    # Send client our public key
    writer.write(
        ffdh.public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    await writer.drain()

    # Compute shared secret
    shared_secret = ffdh.exchange(client_pk)  # type: ignore

    # Hash shared secret to get keys
    digest = hashes.Hash(hashes.SHA512())
    digest.update(shared_secret)
    return digest.finalize()


async def handle_connection(reader: StreamReader, writer: StreamWriter):
    """
    gen_secret()
    read_DH()
    compute_shared_secret()
    cipher=create_cipher(KE, KI)
    rq=read_request()
    if rq.type== "GET":
        iv=generate_iv()
        ciphertext=cipher.encrypt(iv, plaintext)
        send(ciphertext)
    """
    # Need to do Diffie-Hellman here to establish shared secret
    key = await get_shared_secret(reader, writer)

    recvd = await read_all(reader)

    # Need to decrypt recvd w/DH secret to get plaintext
    try:
        plaintext = decrypt(recvd, key)
    except ValueError as e:
        print(f"Decryption Error: {e}", file=sys.stderr)

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
        handle_get_request(writer, request, key)
    else:
        print("Bad request!", file=sys.stderr)

    writer.close()


async def main():
    server = await asyncio.start_server(handle_connection,
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
