"""Supplied certificate type, fixed DH group, and signed-field encoding.

Copy this file to src/educrypto/pki_helpers.py in your library.
Certificate issuance and verification belong in educrypto.pki.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from educrypto.dh import DHParameters, DHPublicKey
from educrypto.schnorr import SchnorrSignature


# RFC 7919, Appendix A.1: ffdhe2048, TLS NamedGroup 0x0100.
_FFDHE2048_P = int(
    """
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 61285C97 FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""),
    16,
)
FFDHE2048 = DHParameters(_FFDHE2048_P, 2, (_FFDHE2048_P - 1) // 2)


@dataclass(frozen=True, slots=True)
class Certificate:
    hostname: str
    public_key: DHPublicKey
    expires_at: int
    signature: SchnorrSignature


def encode_certificate_fields(
    hostname: str,
    public_key: DHPublicKey,
    expires_at: int,
) -> bytes:
    """Encode the fields covered by the root signature."""
    return json.dumps({
        "hostname": hostname,
        "public_key": str(public_key.value),
        "expires_at": expires_at,
    }).encode("utf-8")
