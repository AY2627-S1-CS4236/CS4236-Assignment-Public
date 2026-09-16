# Module: educrypto.aead
# Create src/educrypto/aead.py in your library.

from educrypto.hashing import AES_SBOX


def encrypt_mte(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> tuple[bytes, bytes, bytes]: ...

def decrypt_mte(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes | None: ...

def encrypt_etm(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> tuple[bytes, bytes, bytes, bytes]: ...

def decrypt_etm(
    key: bytes,
    ciphertext: bytes,
    tag: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes | None: ...


# Module: educrypto.attacks.week06
# Create src/educrypto/attacks/week06.py in your library.

def solve(base_url: str) -> str: ...
