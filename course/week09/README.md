# Week 9 — LWE public-key encryption

This week has one implementation task: add public-key encryption based on
Learning with Errors (LWE) to your `educrypto` library. The encryption function
accepts bytes and encrypts each bit separately. There is no challenge or attack
entry point for LWE, but you should complete the challenge for last homework. 

The submission of the source code in canvas:
- Homework 7: Week 08 implementation (DHKE) and challenge attack
- Homework 8: Week 09 implementation (LWE)

Create the implementation in your own library repository, not in this
course-material repository. `api.pyi` is the compact signature reference.
Copy the supplied helper first, then implement the three LWE functions below.

## Public parameters and representations

Create `src/educrypto/lwe.py` with this frozen, slotted data class:

~~~python
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class LWEParameters:
    p: int = 12289
    n: int = 704
    m: int = 10240
    error_bound: int = 2

parameters = LWEParameters()
~~~

`LWEParameters()` groups the public modulus, dimensions, and error radius in one
immutable object. Use its default values for the assignment; do not generate a
new prime. Key generation accepts a parameter object and both returned keys
store that object. Encryption and decryption use the parameters stored in their
key. Accept valid supplied parameters without validation; the numerical security
and correctness assessments below apply to the default values.

We write the prime modulus as `p` in mathematics and use `parameters.p` in Python.
All cryptographic additions and multiplications are modulo `p`. Use ordinary Python
integers and `% parameters.p`; do not use floating-point arithmetic or numerical
libraries. The dimensions `n` and `m` mean `parameters.n` and `parameters.m`.

| Value | Shape | Representation |
| --- | --- | --- |
| `A` | `m` rows, `n` columns | Row-major `list[list[int]]` |
| `s` | `n` entries | Flat `list[int]` |
| `e`, `t`, `r` | `m` entries each | Flat `list[int]` |
| Ciphertext `u` | `n` entries | Flat `list[int]` |
| Ciphertext `v` | One field element | `int` |

Entries of `A`, `s`, `t`, `u`, and `v` are represented by integers in
`0 <= value < parameters.p`. Errors are signed integers in
`[-parameters.error_bound, parameters.error_bound]`.
The error radius is denoted by `η` (eta) in mathematics. Entries of `r` are
binary integers, each equal to `0` or `1`.

Inputs are correctly typed and have the specified shapes. Matrix helpers receive
compatible, nonempty rectangular matrices and a positive integer modulus.
Ciphertext lists have a length divisible by eight. Defensive validation is not
required. Do not modify input keys, matrices, vectors, or ciphertext lists.

## Supplied helpers

Copy `course/week09/lwe_helpers.py` to `src/educrypto/lwe_helpers.py` in your
library. This is a complete helper implementation using Python loops and
integers. Reuse it in your LWE implementation; no additional package is needed.

~~~python
def matrix_multiply(
    left: list[list[int]],
    right: list[list[int]],
    *,
    modulus: int,
) -> list[list[int]]:
    ...

def transpose(matrix: list[list[int]]) -> list[list[int]]:
    ...

def bytes_to_bits(data: bytes) -> list[int]:
    ...

def bits_to_bytes(bits: list[int]) -> bytes:
    ...
~~~

`matrix_multiply` returns the modular product in a new matrix. For an `a × b`
left matrix and a `b × c` right matrix, the result is `a × c`. `transpose`
interchanges rows and columns and also returns new lists.

~~~python
matrix_multiply([[1, 2], [3, 4]], [[5], [6]], modulus=17) == [[0], [5]]
transpose([[1, 2, 3], [4, 5, 6]]) == [[1, 4], [2, 5], [3, 6]]
~~~

The helpers treat a column vector as a matrix with one column. For example,
the flat vector `[3, 4]` becomes `[[3], [4]]`; a row vector is `[[3, 4]]`.
Convert the resulting one-column or one-row matrix back to a flat vector when
storing key or ciphertext fields. Pass `modulus=parameters.p` for LWE arithmetic.

`bytes_to_bits` preserves byte order and expands each byte most significant bit
first. `bits_to_bytes` packs groups of eight bits in the same order. Its input
contains only `0` and `1` and has a length divisible by eight. Both helpers
support empty input and preserve leading zeros.

~~~python
bytes_to_bits(b"\x00\x81") == [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1]
bits_to_bytes([0, 0, 0, 0, 0, 0, 0, 1]) == b"\x01"
bytes_to_bits(b"") == []
bits_to_bytes([]) == b""
~~~

## Key and ciphertext types

Define these three data classes in `educrypto.lwe`:

~~~python
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class LWEPublicKey:
    parameters: LWEParameters
    A: list[list[int]]
    t: list[int]

@dataclass(frozen=True, slots=True)
class LWEPrivateKey:
    parameters: LWEParameters
    s: list[int]

@dataclass(frozen=True, slots=True)
class LWEBitCiphertext:
    u: list[int]
    v: int
~~~

`frozen=True` prevents reassigning fields, and `slots=True` prevents arbitrary
extra attributes. The contained lists remain mutable, so preserve them when
using a key or ciphertext. The public key can be shared. Keep the private key
secret. Public parameters are not secret, including those stored with the
private key. Neither the key-generation errors nor encryption randomness are
fields of a returned key or ciphertext. Both keys from one key pair share the
same parameter object.

## Generate a key pair

~~~python
def generate_keypair(
    parameters: LWEParameters = LWEParameters(),
) -> tuple[LWEPublicKey, LWEPrivateKey]:
    ...
~~~

The omitted argument uses the default parameters. For supplied parameters:

1. Sample every entry of `A` independently with `secrets.randbelow(parameters.p)`.
2. Sample each entry of `s` independently with `secrets.randbelow(parameters.p)`,
   including zero as a valid choice.
3. Sample each entry of `e` independently with
   `secrets.randbelow(2 * parameters.error_bound + 1) - parameters.error_bound`.
   With the default radius, each of `-2, -1, 0, 1, 2` has probability `1/5`.
4. Compute `t = (A s + e) mod p`, reducing every entry to `0..parameters.p-1`.
5. Return `(LWEPublicKey(parameters, A, t), LWEPrivateKey(parameters, s))`,
   public key first.

Use fresh, independent samples for each call. Discard `e` after computing `t`.

## Encrypt bytes, one bit at a time

~~~python
def encrypt(
    public_key: LWEPublicKey, plaintext: bytes
) -> list[LWEBitCiphertext]:
    ...
~~~

Read `parameters = public_key.parameters`. Use `bytes_to_bits` and loop through
the bits in order. For each bit `b`:

1. Sample a new length-`parameters.m` vector `r`, using `secrets.randbelow(2)` for
   every entry. All entries and all vectors for different bits are independent.
   Accept the all-zero vector; do not resample it.
2. Compute these values modulo `p`:

   ~~~text
   u = rᵀ A
   v = rᵀ t + (p // 2) * b
   ~~~

3. Append `LWEBitCiphertext(u, v)` to the output list.

`p // 2` is integer division: the default bit-one offset is exactly `6144`.
The transpose symbol `ᵀ` turns the column vector `r` into a row vector. Equivalently, compute
the column vector `Aᵀ r` and flatten it to obtain `u`.

Do not share `r` between bits or calls. Do not add another error term during
encryption. Preserve the bit order and return one ciphertext object per bit:

~~~text
len(ciphertext) = 8 * len(plaintext)
~~~

Encrypting `b""` returns `[]`. Encryption handles bytes directly; callers are
responsible for any text encoding.

## Decrypt and repack bytes

~~~python
def decrypt(
    private_key: LWEPrivateKey, ciphertext: list[LWEBitCiphertext]
) -> bytes:
    ...
~~~

Read `parameters = private_key.parameters`. For each ciphertext object, in order:

1. Compute `x = (v - u·s) % parameters.p`, where `u·s` is the dot product.
2. Calculate the circular distances to the two possible bit centers:

   ~~~text
   h  = p // 2
   d0 = min(x, p - x)
   d1 = min((x - h) mod p, (h - x) mod p)
   ~~~

3. Recover `0` if `d0 <= d1`, including a tie, and `1` otherwise.

Pack the recovered bits using `bits_to_bytes` and return the bytes. An empty
ciphertext returns `b""`. This construction has no authentication check;
decryption does not return `None` or detect ciphertext changes.

~~~python
from educrypto.lwe import LWEParameters, generate_keypair, encrypt, decrypt

parameters = LWEParameters()
public_key, private_key = generate_keypair(parameters)
assert public_key.parameters == private_key.parameters == parameters
message = b"\x00\x81"
ciphertext = encrypt(public_key, message)
assert len(ciphertext) == 16
assert decrypt(private_key, ciphertext) == message
~~~

These matrices are large. Key generation and encryption can take several seconds
in ordinary Python. Start with one- or two-byte messages and reuse a key pair
when trying several messages.

## Why decoding works

Substituting the public-key formula cancels the term containing `A`:

~~~text
v - u·s = rᵀ e + (p // 2) * b  (mod p)
~~~

The following numerical bounds use the default parameters. The remaining sum
`rᵀe` is the accumulated noise. If its integer magnitude is
strictly below `3072`, decoding chooses the intended bit center. The largest
possible magnitude is `parameters.m * parameters.error_bound = 20480`, so
correctness is not guaranteed for every possible random draw or every possible
error vector. For independent
sampling as specified, the calculated failure probability is below `2^-660`
per bit, averaged over key generation and encryption randomness. Consequently,
the round-trip examples succeed with overwhelming probability.

This is Regev-style public-key encryption with uniform bounded errors.
Its CPA security assumes decisional LWE is hard for the specified distribution.
The row count gives binary `r` enough entropy for the subset-sum security
argument. The fixed parameters were checked against heuristic classical
attack-cost models targeting 128-bit security; this is not a claim that the
original Gaussian lattice-hardness theorem directly applies to these uniform
errors. See [Regev's construction](https://cims.nyu.edu/~regev/papers/qcrypto.pdf)
and the [Lattice Estimator](https://github.com/malb/lattice-estimator).

## Setup and feedback

No new dependency is needed. From your library repository, after copying the
helper and creating `lwe.py`, install your library in editable mode:

~~~bash
python3 -m pip install -e '.[test]'
~~~

From the course-material repository, use the same Python environment:

~~~bash
python3 -m pytest -q course/week09 -s
~~~

On Windows PowerShell:

~~~powershell
py -m pip install -e '.[test]'
# Run this from the course-material repository:
py -m pytest -q course/week09 -s
~~~

Every Week 09 feedback test is an ordinary implementation test.
