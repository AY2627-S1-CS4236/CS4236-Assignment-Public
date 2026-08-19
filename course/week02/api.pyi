# Module: educrypto.spn
# Create src/educrypto/spn.py in your library.

# declare a constant BLOCK_SIZE = 16
BLOCK_SIZE = 16

def substitute(state: bytes, *, sbox: bytes) -> bytes: ...
def inverse_substitute(state: bytes, *, sbox: bytes) -> bytes: ...

def permute(state: bytes) -> bytes: ...
def inverse_permute(state: bytes) -> bytes: ...

def expand_key(
    key: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> tuple[bytes, ...]: ...

def encrypt_block(
    key: bytes,
    plaintext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def decrypt_block(
    key: bytes,
    ciphertext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes: ...


# Module: educrypto.attacks.week02
# Create src/educrypto/attacks/week02.py in your library.

def solve(base_url: str) -> str: ...
