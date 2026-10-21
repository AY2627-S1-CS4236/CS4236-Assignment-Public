"""Week 09 Regev-style encryption with fixed educational parameters."""

from dataclasses import dataclass
import secrets

from .lwe_helpers import bits_to_bytes, bytes_to_bits, matrix_multiply, transpose


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
) -> tuple[LWEPublicKey, LWEPrivateKey]:
    """Sample A and s over F_p, add independent uniform signed errors."""

    p, n, m, error_bound = (
        parameters.p, parameters.n, parameters.m, parameters.error_bound
    )
    A = [[secrets.randbelow(p) for _ in range(n)] for _ in range(m)]
    s = [secrets.randbelow(p) for _ in range(n)]
    e = [secrets.randbelow(2 * error_bound + 1) - error_bound for _ in range(m)]
    product = matrix_multiply(A, [[value] for value in s], modulus=p)
    t = [(row[0] + error) % p for row, error in zip(product, e)]
    return LWEPublicKey(parameters, A, t), LWEPrivateKey(parameters, s)


def encrypt(
    public_key: LWEPublicKey, plaintext: bytes
) -> list[LWEBitCiphertext]:
    """Encrypt bytes with a fresh independent binary selector for each bit."""

    if not plaintext:
        return []
    parameters = public_key.parameters
    p = parameters.p
    columns = transpose(public_key.A)
    output = []
    for bit in bytes_to_bits(plaintext):
        r = [secrets.randbelow(2) for _ in range(parameters.m)]
        product = matrix_multiply(columns, [[value] for value in r], modulus=p)
        u = [row[0] for row in product]
        v = (matrix_multiply([r], [[value] for value in public_key.t], modulus=p)[0][0]
             + (p // 2) * bit) % p
        output.append(LWEBitCiphertext(u, v))
    return output


def decrypt(
    private_key: LWEPrivateKey, ciphertext: list[LWEBitCiphertext]
) -> bytes:
    """Decode each noisy bit by circular distance, then restore byte order."""

    bits = []
    p = private_key.parameters.p
    s_column = [[value] for value in private_key.s]
    h = p // 2
    for bit in ciphertext:
        dot_product = matrix_multiply([bit.u], s_column, modulus=p)[0][0]
        x = (bit.v - dot_product) % p
        d0 = min(x, p - x)
        d1 = min((x - h) % p, (h - x) % p)
        bits.append(0 if d0 <= d1 else 1)
    return bits_to_bytes(bits)
