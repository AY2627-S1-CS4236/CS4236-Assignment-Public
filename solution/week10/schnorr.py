"""Finite-field Schnorr signatures for Week 10."""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from . import dh
from .dh import DHParameters, DHPrivateKey, DHPublicKey
from .hashing import sponge_hash


@dataclass(frozen=True, slots=True)
class SchnorrSignature:
    R: int
    s: int


def generate_keypair(parameters: DHParameters) -> tuple[DHPublicKey, DHPrivateKey]:
    """Reuse the Week 8 key generator, with the public key first."""
    return dh.generate_keypair(parameters)


def hash(parameters: DHParameters, R: int, message: bytes) -> int:
    width = (parameters.p.bit_length() + 7) // 8
    digest = sponge_hash(
        R.to_bytes(width, "big") + message,
        c=8,
        digest_length=32,
        rounds=20,
    )
    return int.from_bytes(digest, "big") % parameters.q


def sign(private_key: DHPrivateKey, message: bytes) -> SchnorrSignature:
    """Draw an independent nonzero nonce for every signature."""

    parameters = private_key.parameters
    k = secrets.randbelow(parameters.q - 1) + 1
    R = pow(parameters.g, k, parameters.p)
    r = hash(parameters, R, message)
    return SchnorrSignature(R, (k + r * private_key.exponent) % parameters.q)


def verify(
    public_key: DHPublicKey, message: bytes, signature: SchnorrSignature
) -> bool:
    """Check canonical signature ranges, subgroup membership, and the equation."""

    parameters = public_key.parameters
    R, s = signature.R, signature.s
    if not 1 <= R < parameters.p or not 0 <= s < parameters.q:
        return False
    if pow(R, parameters.q, parameters.p) != 1:
        return False
    r = hash(parameters, R, message)
    return pow(parameters.g, s, parameters.p) == (
        R * pow(public_key.value, r, parameters.p)
    ) % parameters.p
