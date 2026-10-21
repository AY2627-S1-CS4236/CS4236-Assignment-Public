"""Finite-field Diffie–Hellman for the Week 08 course material."""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from .encoding import int_to_bytes
from .hashing import sponge_hash
from .primality import is_probable_prime


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


def generate_parameters(*, bits: int = 256) -> DHParameters:
    """Generate a safe-prime group with a random order-q generator."""

    while True:
        q = (1 << (bits - 2)) | secrets.randbits(bits - 2) | 1
        if not is_probable_prime(q):
            continue
        p = 2 * q + 1
        if is_probable_prime(p):
            break
    while True:
        g = secrets.randbelow(p - 1) + 1
        if g in (1, p - 1):
            continue
        if pow(g, q, p) == 1:
            return DHParameters(p, g, q)


def generate_keypair(parameters: DHParameters) -> tuple[DHPublicKey, DHPrivateKey]:
    """Create a public and private key in the caller's group."""

    x = secrets.randbelow(parameters.q - 1) + 1
    public = DHPublicKey(parameters, pow(parameters.g, x, parameters.p))
    private = DHPrivateKey(parameters, x)
    return public, private


def derive_shared_key(
    private_key: DHPrivateKey, peer_public_key: DHPublicKey
) -> int:
    """Return the common group element, before any key derivation or encoding."""

    return pow(
        peer_public_key.value,
        private_key.exponent,
        private_key.parameters.p,
    )


def derive_shared_key_bytes(shared_key: int, *, length: int) -> bytes:
    """Derive the requested number of bytes with the Week 5 sponge."""

    return sponge_hash(int_to_bytes(shared_key), c=8, digest_length=length, rounds=20)
