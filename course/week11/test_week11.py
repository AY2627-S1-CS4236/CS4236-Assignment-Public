"""Public feedback for Week 11 root-signed certificates and the relay game."""

from dataclasses import replace
import importlib
import json
import secrets

import pytest


def _modules():
    return (
        importlib.import_module("educrypto.dh"),
        importlib.import_module("educrypto.pki_helpers"),
        importlib.import_module("educrypto.pki"),
        importlib.import_module("educrypto.schnorr"),
    )


@pytest.fixture(scope="module")
def credentials():
    dh, helper, pki, _ = _modules()
    now = 2_000_000_000
    root_public, root_private = dh.generate_keypair(helper.FFDHE2048)
    server_public, _ = dh.generate_keypair(helper.FFDHE2048)
    certificate = pki.issue_certificate(
        root_private, "vault.course.test", server_public, now + 60
    )
    return now, root_public, certificate


def test_fixed_certificate_group():
    _, helper, _, _ = _modules()
    parameters = helper.FFDHE2048
    assert parameters.p.bit_length() == 2048
    assert parameters.g == 2
    assert parameters.q == (parameters.p - 1) // 2
    assert pow(parameters.g, parameters.q, parameters.p) == 1


def test_certificate_signature_hostname_root_and_expiry(credentials):
    dh, helper, pki, schnorr = _modules()
    now, root_public, certificate = credentials

    def valid(candidate, *, root=root_public, name="vault.course.test", at=now):
        return pki.verify_certificate(candidate, root, hostname=name, now=at)

    assert valid(certificate)
    assert valid(certificate, at=0)
    assert valid(certificate, at=now + 60)
    assert not valid(certificate, at=now + 61)
    assert not valid(certificate, name="other.course.test")

    other_root, _ = dh.generate_keypair(helper.FFDHE2048)
    other_server, _ = dh.generate_keypair(helper.FFDHE2048)
    assert not valid(certificate, root=other_root)
    assert not valid(replace(certificate, hostname="other.course.test"))
    assert not valid(replace(certificate, public_key=other_server))
    assert not valid(replace(certificate, expires_at=now + 61))
    changed_signature = replace(
        certificate.signature,
        s=(certificate.signature.s + 1) % helper.FFDHE2048.q,
    )
    assert not valid(replace(certificate, signature=changed_signature))

    encoded = helper.encode_certificate_fields(
        certificate.hostname, certificate.public_key, certificate.expires_at
    )
    fields = {
        "hostname": certificate.hostname,
        "public_key": str(certificate.public_key.value),
        "expires_at": certificate.expires_at,
    }
    assert json.loads(encoded) == fields
    assert schnorr.verify(root_public, encoded, certificate.signature)


@pytest.mark.attack
def test_solver_returns_exact_startup_secret():
    from course.week11.challenge.server import running_server

    attack = importlib.import_module("educrypto.attacks.week11")
    secret = f"Week 11 {secrets.token_hex(12)} — π 🔑"
    with running_server(secret=secret) as server:
        assert attack.solve(server.base_url) == secret
