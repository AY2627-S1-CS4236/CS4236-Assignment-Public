# Module: educrypto.schnorr
# Reuse the Week 8 DH types; create src/educrypto/schnorr.py in your library.
# Copy the supplied key-generation wrapper; implement the remaining functions.

from dataclasses import dataclass
from educrypto import dh
from educrypto.dh import DHParameters, DHPrivateKey, DHPublicKey


@dataclass(frozen=True, slots=True)
class SchnorrSignature:
    R: int
    s: int


def generate_keypair(parameters: DHParameters) -> tuple[DHPublicKey, DHPrivateKey]:
    return dh.generate_keypair(parameters)


def hash(parameters: DHParameters, R: int, message: bytes) -> int: ...


def sign(private_key: DHPrivateKey, message: bytes) -> SchnorrSignature: ...


def verify(
    public_key: DHPublicKey, message: bytes, signature: SchnorrSignature
) -> bool: ...


# Module: educrypto.attacks.week10
# Create src/educrypto/attacks/week10.py in your library.

def solve(base_url: str) -> str: ...
