# Copy course/week11/pki_helpers.py to src/educrypto/pki_helpers.py.
# The helper supplies FFDHE2048, Certificate, and encode_certificate_fields.
# The challenge server's internal protocol code is not part of this API.

from educrypto.dh import DHPrivateKey, DHPublicKey
from educrypto.pki_helpers import Certificate


# Module: educrypto.pki
def issue_certificate(
    root_private_key: DHPrivateKey,
    hostname: str,
    server_public_key: DHPublicKey,
    expires_at: int,
) -> Certificate: ...


def verify_certificate(
    certificate: Certificate,
    root_public_key: DHPublicKey,
    *,
    hostname: str,
    now: int,
) -> bool: ...


# Module: educrypto.attacks.week11
def solve(base_url: str) -> str: ...
