# Module: educrypto.mac
# Create src/educrypto/mac.py in your library.

def cmac(
    key: bytes,
    message: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def verify_cmac(
    key: bytes,
    message: bytes,
    tag: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bool: ...

def pfmac(
    key: bytes,
    message: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes: ...

def verify_pfmac(
    key: bytes,
    message: bytes,
    tag: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bool: ...


# Module: educrypto.attacks.week04
# Create src/educrypto/attacks/week04.py in your library.

def solve(base_url: str) -> str: ...
