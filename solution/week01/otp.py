# You can import functions from other files
from educrypto.encoding import xor_bytes

import math

def encrypt(pad: bytes, plaintext: bytes) -> bytes: 
    extended_pad = pad * math.ceil(len(plaintext) / len(pad))
    return xor_bytes(extended_pad, plaintext)

def decrypt(pad: bytes, ciphertext: bytes) -> bytes: 
    extended_pad = pad * math.ceil(len(ciphertext) / len(pad))
    return xor_bytes(extended_pad, ciphertext)

