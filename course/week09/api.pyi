# Module: educrypto.lwe_helpers
# Copy the supplied course/week09/lwe_helpers.py into your library.

def matrix_multiply(
    left: list[list[int]],
    right: list[list[int]],
    *,
    modulus: int,
) -> list[list[int]]: ...

def transpose(matrix: list[list[int]]) -> list[list[int]]: ...

def bytes_to_bits(data: bytes) -> list[int]: ...

def bits_to_bytes(bits: list[int]) -> bytes: ...


# Module: educrypto.lwe
# Create src/educrypto/lwe.py in your library.

from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class LWEParameters:
    p: int = 12289
    n: int = 704
    m: int = 10240
    error_bound: int = 2


@dataclass(frozen=True, slots=True)
class LWEPublicKey:
    parameters: LWEParameters
    A: list[list[int]]
    t: list[int]


@dataclass(frozen=True, slots=True)
class LWEPrivateKey:
    parameters: LWEParameters
    s: list[int]


@dataclass(frozen=True, slots=True)
class LWEBitCiphertext:
    u: list[int]
    v: int


def generate_keypair(
    parameters: LWEParameters = LWEParameters(),
) -> tuple[LWEPublicKey, LWEPrivateKey]: ...

def encrypt(
    public_key: LWEPublicKey, plaintext: bytes
) -> list[LWEBitCiphertext]: ...

def decrypt(
    private_key: LWEPrivateKey, ciphertext: list[LWEBitCiphertext]
) -> bytes: ...
