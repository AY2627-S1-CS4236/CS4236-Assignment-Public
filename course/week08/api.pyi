# Module: educrypto.primality
# Copy the supplied course/week08/primality.py to src/educrypto/primality.py.

def is_probable_prime(n: int) -> bool: ...


# Module: educrypto.dh
# Create src/educrypto/dh.py in your library.

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DHParameters:
    p: int
    g: int
    q: int


@dataclass(frozen=True, slots=True)
class DHPublicKey:
    parameters: DHParameters
    value: int


@dataclass(frozen=True, slots=True)
class DHPrivateKey:
    parameters: DHParameters
    exponent: int


def generate_parameters(*, bits: int = 256) -> DHParameters: ...


def generate_keypair(parameters: DHParameters) -> tuple[DHPublicKey, DHPrivateKey]: ...


def derive_shared_key(
    private_key: DHPrivateKey, peer_public_key: DHPublicKey
) -> int: ...


def derive_shared_key_bytes(shared_key: int, *, length: int) -> bytes: ...


# Module: educrypto.attacks.week08
# Create src/educrypto/attacks/week08.py in your library.

def solve(base_url: str) -> str: ...
