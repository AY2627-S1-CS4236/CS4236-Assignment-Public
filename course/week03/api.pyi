# Module: educrypto.modes
# Create src/educrypto/modes.py in your library.

def pkcs7_pad(data: bytes) -> bytes: ...

def pkcs7_unpad(padded_data: bytes) -> bytes: ...

def encrypt_ecb(
    key: bytes,
    plaintext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def decrypt_ecb(
    key: bytes,
    ciphertext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def encrypt_cbc(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def decrypt_cbc(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def encrypt_ctr(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def decrypt_ctr(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes: ...


# Module: educrypto.attacks.week03
# Create src/educrypto/attacks/week03.py in your library.

def solve(base_url: str) -> str: ...
