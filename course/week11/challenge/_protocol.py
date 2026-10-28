"""Internal protocol mechanics for the Week 11 challenge server.

Handshake messages and records stay as JSON dictionaries; session keys
remain local to the service.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Any

from educrypto import aead, dh, pki, schnorr
from educrypto.pki_helpers import Certificate, FFDHE2048
from educrypto.schnorr import SchnorrSignature


GROUP_ID = 256
_MAX_MESSAGE_BYTES = 4096
_MAX_SEQUENCE = 1 << 64


@dataclass(slots=True)
class Session:
    role: str
    key: bytes
    send_sequence: int = 0
    receive_sequence: int = 0


def _decimal(value: Any) -> int:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or not value.isascii()
        or not value.isdigit()
    ):
        raise ValueError("expected a decimal string")
    return int(value, 10)


def _key(value: str) -> dh.DHPublicKey:
    return dh.DHPublicKey(FFDHE2048, _decimal(value))


def _signature(value: dict[str, str]) -> SchnorrSignature:
    return SchnorrSignature(_decimal(value["R"]), _decimal(value["s"]))


def _certificate(value: dict[str, Any]) -> Certificate:
    return Certificate(
        value["hostname"],
        _key(value["public_key"]),
        value["expires_at"],
        _signature(value["signature"]),
    )


def _certificate_json(value: Certificate | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {
        "hostname": value.hostname,
        "public_key": str(value.public_key.value),
        "expires_at": value.expires_at,
        "signature": {"R": str(value.signature.R), "s": str(value.signature.s)},
    }


def _valid_public_key(public_key: dh.DHPublicKey) -> bool:
    if not isinstance(public_key, dh.DHPublicKey) or public_key.parameters != FFDHE2048:
        return False
    value = public_key.value
    return (
        type(value) is int
        and 1 < value < FFDHE2048.p - 1
        and pow(value, FFDHE2048.q, FFDHE2048.p) == 1
    )


def _valid_client_hello(hello: Any) -> bool:
    if not isinstance(hello, dict) or set(hello) != {"server_name", "key_share"}:
        return False
    name = hello["server_name"]
    if (
        not isinstance(name, str)
        or not name
        or not name.isascii()
        or name.lower() != name
        or "*" in name
    ):
        return False
    try:
        return _valid_public_key(_key(hello["key_share"]))
    except (TypeError, ValueError):
        return False


def _session(
    private_key: dh.DHPrivateKey,
    peer_public_key: dh.DHPublicKey,
    *,
    role: str,
) -> Session:
    shared = dh.derive_shared_key(private_key, peer_public_key)
    return Session(role, dh.derive_shared_key_bytes(shared, length=48))


def create_client_hello(server_name: str) -> tuple[dict[str, str], dh.DHPrivateKey]:
    """Generate a JSON ClientHello and retain its ephemeral private key."""
    public, private = dh.generate_keypair(FFDHE2048)
    return {"server_name": server_name, "key_share": str(public.value)}, private


def create_server_hello(
    client_hello: dict[str, Any],
    signing_private_key: dh.DHPrivateKey,
    certificate: Certificate | dict[str, Any],
) -> tuple[dict[str, Any], Session]:
    """Sign a fresh server share using the certificate holder's key."""
    if not _valid_client_hello(client_hello):
        raise ValueError("invalid ClientHello")
    certificate_json = _certificate_json(certificate)
    if client_hello["server_name"] != certificate_json["hostname"]:
        raise ValueError("requested hostname does not match the server certificate")
    public, private = dh.generate_keypair(FFDHE2048)
    share = str(public.value)
    signature = schnorr.sign(signing_private_key, share.encode("utf-8"))
    return (
        {
            "key_share": share,
            "certificate": certificate_json,
            "signature": {"R": str(signature.R), "s": str(signature.s)},
        },
        _session(private, _key(client_hello["key_share"]), role="server"),
    )


def accept_server_hello(
    client_hello: dict[str, Any],
    client_private_key: dh.DHPrivateKey,
    server_response: dict[str, Any],
    root_public_key: dh.DHPublicKey | str,
    *,
    now: int,
) -> Session | None:
    """Verify the certificate and signed server share before using keys."""
    if not isinstance(server_response, dict) or set(server_response) != {
        "key_share", "certificate", "signature"
    }:
        return None
    try:
        server_share = _key(server_response["key_share"])
        certificate = _certificate(server_response["certificate"])
        signature = _signature(server_response["signature"])
        trusted_root = (
            root_public_key
            if isinstance(root_public_key, dh.DHPublicKey)
            else _key(root_public_key)
        )
    except (KeyError, TypeError, ValueError):
        return None
    if not _valid_public_key(server_share):
        return None
    if not pki.verify_certificate(
        certificate, trusted_root, hostname=client_hello["server_name"], now=now
    ):
        return None
    if not schnorr.verify(
        certificate.public_key, server_response["key_share"].encode("utf-8"), signature
    ):
        return None
    return _session(client_private_key, server_share, role="client")


def send_message(session: Session, plaintext: bytes) -> dict[str, str]:
    """Encrypt a plaintext and return its JSON record."""
    sequence = session.send_sequence
    sequence_text = str(sequence)
    iv = secrets.token_bytes(8)
    direction = "0" if session.role == "client" else "1"
    associated_data = direction.encode() + sequence_text.encode()
    _, _, ciphertext, tag = aead.encrypt_etm(
        session.key, plaintext,
        iv=iv, associated_data=associated_data, rounds=20,
    )
    session.send_sequence += 1
    return {
        "direction": direction,
        "sequence": sequence_text,
        "iv_hex": iv.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
    }


def receive_message(session: Session, record: dict[str, Any]) -> bytes | None:
    """Accept only the next authenticated JSON record in this direction."""
    if not isinstance(record, dict) or set(record) != {
        "direction", "sequence", "iv_hex", "ciphertext_hex", "tag_hex"
    }:
        return None
    try:
        record_sequence = _decimal(record["sequence"])
        iv = bytes.fromhex(record["iv_hex"])
        ciphertext = bytes.fromhex(record["ciphertext_hex"])
        tag = bytes.fromhex(record["tag_hex"])
    except (KeyError, TypeError, ValueError):
        return None
    sequence = session.receive_sequence
    expected_direction = "1" if session.role == "client" else "0"
    if record["direction"] != expected_direction:
        return None
    if not 0 <= sequence < _MAX_SEQUENCE or record_sequence != sequence:
        return None
    if len(iv) != 8 or len(ciphertext) > _MAX_MESSAGE_BYTES or len(tag) != 16:
        return None
    associated_data = record["direction"].encode() + record["sequence"].encode()
    plaintext = aead.decrypt_etm(
        session.key,
        ciphertext, tag,
        iv=iv, associated_data=associated_data, rounds=20,
    )
    if plaintext is not None:
        session.receive_sequence += 1
    return plaintext
