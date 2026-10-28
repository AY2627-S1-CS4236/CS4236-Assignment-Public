# Week 11 — Public-key infrastructure

This week has two parts:

1) Extend your `educrypto` library with a root-signed server certificate
   and its verification policy.
2) Play an active man-in-the-middle (MITM) challenge: the root CA's
   **signing private key is disclosed**, and your goal is to learn the
   second of two messages the Client sends in the **same Client session**.
   Your relay to the real Server uses a separate connection.

Implement `educrypto.pki` and `educrypto.attacks.week11` in your own
library. The challenge server implements its handshake, key derivation,
and protected-record operations internally. Those operations are not a
new library API; your solver can use the primitives from earlier weeks.
The relay is an educational protocol assembled from this course's DH,
Schnorr, hash, and encrypt-then-MAC functions, and is not interoperable
with TLS 1.3.

## Earlier APIs and supplied code

Complete Weeks 8 and 10 first. Certificate issuance and verification
reuse `educrypto.dh` key types and `educrypto.schnorr.sign` and `verify`.
The challenge relay also uses your existing Week 6 authenticated
encryption and course hash functions.

Copy `course/week11/pki_helpers.py` to
`src/educrypto/pki_helpers.py` in your library. It supplies the fixed
group, `Certificate`, and certificate-field encoder.

The supplied `FFDHE2048` group is the
[ffdhe2048 group in RFC 7919](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1):
`DHParameters(p, 2, (p - 1) // 2)`. The challenge uses this fixed group.
Do not generate new group parameters for it.

## Certificate representation

`pki_helpers.py` supplies this frozen data class:

~~~python
@dataclass(frozen=True, slots=True)
class Certificate:
    hostname: str
    public_key: DHPublicKey
    expires_at: int
    signature: SchnorrSignature
~~~

The root signs the hostname, server public key, and expiry directly. The
Client already trusts the root public key; it never learns that key from
the Server. The certificate has one expiry time and no intermediate CA.

The helper also supplies
`encode_certificate_fields(hostname, public_key, expires_at) -> bytes`.
It uses ordinary `json.dumps(...).encode("utf-8")` on fields in a fixed
order, with the public-key integer represented as a decimal string.
Use the supplied function for the signed bytes; changing any field
invalidates the signature.

## Required PKI API

Create `src/educrypto/pki.py` with the signatures in `api.pyi`:

~~~python
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
~~~

`issue_certificate` assumes valid local issuer inputs. Sign this message
with the Week 10 Schnorr function and return a `Certificate`:

~~~text
encode_certificate_fields(hostname, server_public_key, expires_at)
~~~

`verify_certificate` assumes the certificate, keys, signature, hostname,
and integer Unix times are well formed. Return `False` if the certificate
hostname differs from the requested hostname, if `now > expires_at`, or
if the root signature does not verify over the signed certificate fields.
The expiry second itself is valid. Hostname matching is exact and
case-sensitive; there is no wildcard, IDNA, or Common Name fallback.
Do not alter either input.

For example, with locally generated keys:

~~~python
certificate = issue_certificate(
    root_private_key, "vault.course.test", server_public_key, now + 3600
)
assert verify_certificate(
    certificate, root_public_key, hostname="vault.course.test", now=now
)
~~~

The public tests exercise the signed representation, hostname matching,
expiry, and signature verification.

## MITM challenge

The service discloses the trusted root CA's signing exponent and public
key. The real Server's signing private key and the Client's and Server's
ephemeral DH private keys remain hidden. The Client sends two application
plaintexts in one session.

The Server signs only its decimal `key_share` encoded as UTF-8. The Client
verifies that signature with the public key in the server certificate.

The application plaintexts are:

~~~text
First Message (Client to Server):
C1 = 32 fresh random bytes from the Client

First Response (Server to Client):
S1 = H(C1 || server_nonce)

Second Message (Client to Server):
C2 = H(S1 || client_new_nonce)
~~~


Here `H(data) = sponge_hash(data, c=8, digest_length=32, rounds=20)`,
and each nonce is 32 fresh bytes.

The Server and Client use the plaintext they decrypt from each relayed record,
even if the Player changed it.

Recover all 32 bytes of `C2` and submit its hexadecimal
value. One correct answer reveals the exact startup secret.

Create `src/educrypto/attacks/week11.py` with this entry point:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Use the supplied URL to create and win one game, then return the secret
from the successful guess response. Do not start the service, read its
environment or private state, assume a fixed port, or guess its secret.
The [challenge instructions](challenge/README.md) show the request JSON
for each exchange, along with the browser workflow, response shapes, and
error behavior.

## Setup and feedback

Copy `pki_helpers.py` into your library and install it in editable mode:

~~~bash
python3 -m pip install -e '.[test]'
~~~

From the course-material repository, install the challenge dependency and run:

~~~bash
python3 -m pip install -r course/week11/challenge/requirements.txt
python3 -m pytest -q course/week11 -m "not attack" -s
python3 -m pytest -q course/week11 -m "attack" -s
python3 -m pytest -q course/week11 -s
~~~

On Windows PowerShell, use `py` in place of `python3`.
