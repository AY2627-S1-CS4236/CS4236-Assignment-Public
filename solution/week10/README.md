# Week 10 — Schnorr signatures

This week has two parts:

1. Implement finite-field Schnorr signatures using the group and key types
   from Week 8's Diffie–Hellman key exchange.
2. Analyze an existential-unforgeability-under-chosen-message-attack
   (EUF-CMA) game whose signing service uses an unusual nonce sequence.
   Produce one valid signature on a fresh message to recover the Server's
   startup secret.

Create the implementation in your own library repository, not in this
course-material repository. `api.pyi` lists the required signatures and provides
the key-generation wrapper below.
Complete Weeks 5 and 8 first: this week reuses their sponge hash and DH API.
No new library dependency is needed.

In Week 4, a MAC used a shared secret key to create and verify tags. A digital
signature uses a private key for signing and a public key for verification.
Anyone with the public key can verify a signature without knowing the private key.

## Group, keys, and signature representation

Create `src/educrypto/schnorr.py`. Import and reuse these existing Week 8 types
from `educrypto.dh`; do not define replacement parameter or key classes:

~~~python
from educrypto.dh import DHParameters, DHPrivateKey, DHPublicKey
~~~

The parameters describe a prime-order subgroup: `p` is prime, `q` is the
prime order of `g`, and `pow(g, q, p) == 1`. The private key stores exponent
`x` in `1..q-1`; the public key stores `y = pow(g, x, p)`. Obtain the group
parameters with Week 8's `educrypto.dh.generate_parameters`.

Define this frozen, slotted data class in `educrypto.schnorr`:

~~~python
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class SchnorrSignature:
    R: int
    s: int
~~~

`R` is a group element, and `s` is an integer modulo `q`. Keep the capital
letter in the field name `R`. All arithmetic uses ordinary Python integers
and modular `pow`; do not use floating-point arithmetic.

Messages are `bytes`, including empty messages and bytes with leading zeros.
Assume correctly typed inputs and valid parameters and keys. Parameter and
key validation is not required, but verification must perform the signature
checks specified below. Do not modify input keys or signatures.

## Generate a key pair

Copy this supplied implementation from `api.pyi` into your `schnorr.py`:

~~~python
from educrypto import dh

def generate_keypair(parameters: DHParameters) -> tuple[DHPublicKey, DHPrivateKey]:
    """Reuse the Week 8 key generator, with the public key first."""
    return dh.generate_keypair(parameters)
~~~

It returns the public key first and retains the supplied parameters.

## Hash challenge r

Implement this helper and call it from both `sign` and `verify`:

~~~python
def hash(parameters: DHParameters, R: int, message: bytes) -> int:
    ...
~~~

Return the integer `r` calculated below, using `p` and `q` from `parameters`,
the signature commitment `R`, and the raw message bytes:

~~~text
L = (p.bit_length() + 7) // 8
encoded_R = R.to_bytes(L, "big")
digest = sponge_hash(encoded_R + message,
                     c=8, digest_length=32, rounds=20)
r = int.from_bytes(digest, "big") % q
~~~

Import and call `educrypto.hashing.sponge_hash` from Week 5, using its default
S-box. Capacity `c` and digest length are measured in **bytes**. Hash only `R`
encoded in exactly `L` bytes, with leading zeros when needed, followed by the
raw message bytes. Do not add other fields or padding yourself.

For example, with `p = 467`, `L = 2`. The commitment `R = 90` is encoded as
`b"\x00\x5a"`. For message `b"CS4236"`, the sponge input is
`b"\x00\x5aCS4236"`. With `q = 233`, the resulting challenge is `r = 21`.

## Sign a message

~~~python
def sign(private_key: DHPrivateKey, message: bytes) -> SchnorrSignature:
    ...
~~~

For `p`, `q`, and `g` from the private key's parameters and
`x = private_key.exponent`:

1. Draw a new independent nonce `k` uniformly from `1..q-1` using
   `secrets.randbelow(q - 1) + 1`. Draw again on every call, even when the
   message is repeated.
2. Compute `R = pow(g, k, p)`.
3. Compute `r = hash(parameters, R, message)`.
4. Compute `s = (k + r*x) % q` and return `SchnorrSignature(R, s)`.

The public API has no nonce argument and no persistent nonce counter.

## Verify a signature

~~~python
def verify(
    public_key: DHPublicKey, message: bytes, signature: SchnorrSignature
) -> bool:
    ...
~~~

Use the parameters stored in the public key and let `y = public_key.value`.
First return `False` if any of these conditions fail:

- `1 <= signature.R < p`
- `pow(signature.R, q, p) == 1`
- `0 <= signature.s < q`

Do not silently reduce out-of-range signature fields modulo `p` or `q`.
Then calculate `r = hash(parameters, signature.R, message)` and return whether:

~~~text
pow(g, signature.s, p) == (signature.R * pow(y, r, p)) % p
~~~

Where `y = g^x` is the public verification key.

Return a Python `bool`. `R == 1` and `s == 0` are allowed values; they must
still satisfy the verification equation.

Use generated parameters for the normal library workflow:

~~~python
from educrypto.dh import generate_parameters
from educrypto.schnorr import generate_keypair, sign, verify

parameters = generate_parameters(bits=256)
public, private = generate_keypair(parameters)
message = b"CS4236 Week 10"
signature = sign(private, message)
assert verify(public, message, signature)
~~~

## Schnorr EUF-CMA challenge

The Server generates ordinary 256-bit DH parameters once at startup. At the
beginning of each game instance, it generates a fresh signing key and samples
one nonce `k` uniformly from `0..q-1`. Each signing request uses the current
nonce with the formulas and hash above, then updates:

~~~text
k = (k + 10) % q
~~~

The first request uses the initial nonce; every successful request advances
it, including repeated messages. The Server signs directly rather than calling
your `sign` function. It calls your `verify` function to check a forgery.

You may request signatures on any byte message up to 4096 bytes, including
the empty message. There is no query limit. Win by submitting a valid signature
on a message whose exact bytes were never submitted to the signing oracle
under the current key.

One successful forgery reveals the exact startup secret. A failed,
well-formed attempt starts a fresh-key instance with a newly sampled nonce and
empty query history. Reset does the same and is also allowed after victory.
Malformed requests do not change state.

Create `src/educrypto/attacks/week10.py` in your own library:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Use the supplied URL to create a game, submit a successful fresh-message
forgery, and return the secret. Do not start a Server, access its environment
or private state, assume a fixed port, or guess the secret. See
`challenge/README.md` for the game rules, browser workflow, and HTTP API.

## Setup and feedback

After adding `schnorr.py`, install your library in editable mode from **your
library repository**:

~~~bash
python3 -m pip install -e '.[test]'
~~~

From the **course-material repository**, using the same environment:

~~~bash
python3 -m pip install -r course/week10/challenge/requirements.txt
python3 -m pytest -q course/week10 -m "not attack" -s
python3 -m pytest -q course/week10 -m "attack" -s
python3 -m pytest -q course/week10 -s
~~~

On Windows PowerShell, replace `python3` with `py` in these commands.
Finish the library feedback first, then implement your attack and run the
complete weekly suite. Public tests cover representative behavior; follow the
complete written specification.
