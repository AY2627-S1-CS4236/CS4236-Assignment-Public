# Week 8 — Diffie–Hellman key exchange

This week has two parts:

1. Add finite-field Diffie–Hellman key generation, shared-group-element
   derivation, and a byte-key derivation function to your `educrypto` library.
2. Analyze a chosen-plaintext (CPA) game using ElGamal encryption with unusual
   public group parameters. Win 30 consecutive rounds to recover the Server's
   startup secret.

Create the implementation files in your own library repository, not in this
course-material repository. `api.pyi` is a compact reference for the required
public API. Copy the supplied `primality.py` into your library, then complete
the DH API before the challenge: the Server imports it.

## Supplied primality test

Copy `course/week08/primality.py` to `src/educrypto/primality.py` in your
library repository.

It provides `is_probable_prime(n: int) -> bool`, a complete
Miller–Rabin test with 32 random rounds.

Use this supplied function when
searching for primes; you do not need to implement another primality test or
install a prime-testing package. The helper and your DH arithmetic use
Python's built-in `pow(base, exponent, modulus)` for modular exponentiation.

## Group and key types

Create `src/educrypto/dh.py` with three frozen data classes:

~~~python
@dataclass(frozen=True, slots=True)
class DHParameters:
    p: int  # prime modulus
    g: int  # generator of a prime-order subgroup
    q: int  # order of g

@dataclass(frozen=True, slots=True)
class DHPublicKey:
    parameters: DHParameters
    value: int  # g^x mod p

@dataclass(frozen=True, slots=True)
class DHPrivateKey:
    parameters: DHParameters
    exponent: int  # x
~~~


- `frozen=True` makes instances of the dataclass read-only (immutable).
- `slots=True` tells Python to prevents arbitrary attributes for performance. (e.g., params.custom_field = 123 will fail)

To create an instance of this class do
~~~python
params = DHParameters(p=23, g=5, q=22)
~~~

Use ordinary Python `int` values for all group elements and exponents. The
public key may be sent to another party; the private exponent must remain
secret.

## Generate group parameters

~~~python
def generate_parameters(*, bits: int = 256) -> DHParameters:
    ...
~~~

For a valid integer `bits >= 8`, generate a new group:

1. Choose random odd `(bits - 1)`-bit candidates `q` with python built in `secrets` library, testing
   each with the supplied `is_probable_prime`.

   Use the following statement to generate a random `q`, this ensures that `q` is always an odd number of size `bits - 1`. So you won't accidentally be very unlucky and get a small `q`.
    ~~~python
    q = (1 << (bits - 2)) | secrets.randbits(bits - 2) | 1
    ~~~
2. Set `p = 2*q + 1`. Accept the candidate only if `p` also passes
   `is_probable_prime`. This gives a `bits`-bit probable safe prime.
3. Repeatedly choose a random `g` from `1` through `p - 1` with `secrets.randbelow`.
   Reject `g == 1` and `g == p - 1` (which is `-1 mod p`). Return the first
   `g` for which `pow(g, q, p) == 1`.

Return `DHParameters(p, g, q)`.

## Generate a key pair

~~~python
def generate_keypair(parameters: DHParameters) -> tuple[DHPublicKey, DHPrivateKey]:
    ...
~~~

1. Sample `x` uniformly from `1` through `q - 1` with `secrets`
2. Set `y = pow(g, x, p)`, and return `DHPublicKey(parameters, y)` followed by
`DHPrivateKey(parameters, x)`.

Do not perform any validation on the parameters.

## Derive a shared group element

~~~python
def derive_shared_key(
    private_key: DHPrivateKey, peer_public_key: DHPublicKey
) -> int:
    ...
~~~

Assume both keys use the same valid parameters and return:

~~~text
pow(peer_public_key.value, private_key.exponent, p)
~~~

The returned integer is the shared *group element*.

Two parties must use one shared set of parameters:

~~~python
parameters = generate_parameters(bits=256)
alice_public, alice_private = generate_keypair(parameters)
bob_public, bob_private = generate_keypair(parameters)

alice_shared = derive_shared_key(alice_private, bob_public)
bob_shared = derive_shared_key(bob_private, alice_public)
assert alice_shared == bob_shared
~~~

## Derive key bytes

~~~python
def derive_shared_key_bytes(shared_key: int, *, length: int) -> bytes:
    ...
~~~

This function derives bytes from shared group element so that it can be used as a symmetric-cipher key.

`shared_key` is the positive integer returned by `derive_shared_key`.

`length` is the required keyword-only number of output bytes. Implement the derivation in these exact steps:

~~~python
shared_bytes = int_to_bytes(shared_key)
key_bytes = sponge_hash(shared_bytes, c=8, digest_length=length, rounds=20)
return key_bytes
~~~

- Import and call the Week 1 `educrypto.encoding.int_to_bytes` and Week 5
`educrypto.hashing.sponge_hash` functions.
-  The sponge uses its default S-box. Return exactly the requested number of bytes produced by `sponge_hash`.

~~~python
alice_key = derive_shared_key_bytes(alice_shared, length=32)
bob_key = derive_shared_key_bytes(bob_shared, length=32)
assert alice_key == bob_key
assert len(alice_key) == 32
~~~

This is the course's specified variable-length derivation step. Production
protocols normally use a standard KDF such as HKDF and bind the derived key to
protocol context.

## ElGamal CPA challenge

The Server constructs a prime with the following form once at startup:

~~~text
p = 2 * q_small * q_large + 1
~~~

`q_small` is a random prime below `2^15` and at least `2^14`;
`q_large` is a random 256-bit prime. The Server accepts the result only when
`p` passes its prime check. For a random `a`, the public generator is:

~~~text
g = a^((p - 1) / q_small) mod p
~~~

The Server retries if `g == 1`. The public key for a round is
`h = g^x mod p`, with `x` sampled uniformly from `1` through `p - 1`. For a
numeric message `m` in `1 <= m < p`, ElGamal
encryption chooses a fresh random exponent `k` and returns:

~~~text
c1 = g^k mod p
c2 = m * h^k mod p
~~~

The challenge accepts two distinct **integers**, not byte strings. There is no
encryption oracle: because `p`, `g`, and `h` are public, you can encrypt any
chosen integer locally with the formula above. There is one active challenge
per round. After a guess, the Server creates a fresh private key and the same
game ID continues.
A correct guess adds one win; a wrong guess resets the streak to zero. Thirty
consecutive wins reveal the exact startup secret.

Create `src/educrypto/attacks/week08.py`:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Use the supplied URL, create one game, win 30 rounds, and return the secret
from the final guess. Do not start a Server, read its environment, assume a
fixed port, or guess the secret. The full browser workflow and HTTP API are in
`challenge/README.md`.

## Setup and feedback

No new library dependency is needed. After copying the supplied primality
helper and adding your `dh.py`, install your library in editable mode:

~~~bash
python3 -m pip install -e '.[test]'
~~~

On Windows PowerShell, use `py -m pip install -e '.[test]'`.

From the course-material repository, install the challenge requirement and run
the feedback in that same Python environment:

~~~bash
python3 -m pip install -r course/week08/challenge/requirements.txt
python3 -m pytest -q course/week08 -m "not attack" -s
python3 -m pytest -q course/week08 -m "attack" -s
python3 -m pytest -q course/week08 -s
~~~

On Windows PowerShell, use `py` in place of `python3` for these commands.
