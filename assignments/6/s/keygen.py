#!/usr/bin/env python3

import json
import asyncio
import binascii
import sys
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

client_deck = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

with open("client_deck.pem", "wb") as f:
    f.write(client_deck.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
    
with open("client_enck.pem", "wb") as f:
    f.write(client_deck.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
    
client_sigk = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)
with open("client_sigk.pem", "wb") as f:
    f.write(client_sigk.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
    
with open("client_vrfk.pem", "wb") as f:
    f.write(client_sigk.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
    
    
server_deck = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

with open("server_deck.pem", "wb") as f:
    f.write(server_deck.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
    
with open("server_enck.pem", "wb") as f:
    f.write(server_deck.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
    
server_sigk = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)
with open("server_sigk.pem", "wb") as f:
    f.write(server_sigk.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()))
    
with open("server_vrfk.pem", "wb") as f:
    f.write(server_sigk.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo))
