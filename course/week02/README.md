# Week 2 — Substitution-Permutation Networks

Tasks:

1. Implement the configurable block cipher API specified below.
2. Solve the SeedSafe challenge in the `challenge` folder.

Create the implementation files in your own library repository, not in this
course-material repository. The declarations are also available in `api.pyi`.
Complete the cipher API before starting the challenge because the challenge
server imports your implementation.

This is a teaching cipher, not a secure construction for real applications.
Implement it yourself without delegating its operations to a third-party
cryptography package or command-line program.

## Common rules

Create `src/educrypto/spn.py`

~~~python
BLOCK_SIZE: int = 16
~~~

- All keys, states, plaintext blocks, and ciphertext blocks are `bytes` values
  containing exactly 16 bytes.
- Every function returns a new immutable value and must not mutate its inputs.
- An S-box is supplied as a 256-byte lookup table. It must contain every byte
  value from 0 through 255 exactly once.
- `rounds` must be a positive integer. Callers must provide it explicitly.
- The feedback supplies correctly typed and correctly sized inputs. You may
  assume that callers follow these requirements; defensive error handling is
  not part of the Week 2 assignment.
- This module processes exactly one block at a time. Padding and block modes
  are outside the public Week 2 cipher API.

## Byte substitution

### `substitute`

~~~python
def substitute(state: bytes, *, sbox: bytes) -> bytes:
    ...
~~~

Replace each byte `value` in `state` with `sbox[value]`.

For example, the identity table leaves every valid state unchanged:

~~~python
identity = bytes(range(256))
substitute(bytes(range(16)), sbox=identity) == bytes(range(16))
~~~

### `inverse_substitute`

~~~python
def inverse_substitute(state: bytes, *, sbox: bytes) -> bytes:
    ...
~~~

Derive the inverse lookup table and apply it to every byte. The supplied S-box
is always invertible. For every state and S-box:

~~~python
inverse_substitute(substitute(state, sbox=sbox), sbox=sbox) == state
~~~

## Bit permutation

### `permute`

~~~python
def permute(state: bytes) -> bytes:
    ...
~~~

Number the 128 state bits from 0 through 127. Bit 0 is the most significant
bit of byte 0, bit 7 is the least significant bit of byte 0, and bit 127 is the
least significant bit of byte 15.

Move each input bit at position `i` to this output position:

~~~text
(13 * i + 17) mod 128
~~~

The formula is a permutation because 13 and 128 are coprime. It is a
source-to-destination mapping: the value read from input position `i` is
written to the calculated output position.

### `inverse_permute`

~~~python
def inverse_permute(state: bytes) -> bytes:
    ...
~~~

Apply the exact inverse bit mapping. For every valid state:

~~~python
inverse_permute(permute(state)) == state
permute(inverse_permute(state)) == state
~~~

## Key expansion

### `expand_key`

~~~python
def expand_key(
    key: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> tuple[bytes, ...]:
    ...
~~~

Return the complete sequence of round keys in encryption order:

1. Include the original 16-byte key as `K0`.
2. Interpret the previous key as one unsigned 128-bit big-endian value.
3. Rotate that complete value right by one bit, including wraparound from bit
   127 to bit 0. Do not rotate the individual bytes separately.
4. Apply the supplied S-box to each byte of the rotated value to produce the
   next key.
5. Repeat until keys `K0` through `Krounds` have been produced.

The result is a tuple containing exactly `rounds + 1` 16-byte `bytes` values.
The algorithm does not use round constants.

## Block encryption

### `encrypt_block`

~~~python
def encrypt_block(
    key: bytes,
    plaintext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...
~~~

Expand the key, then encrypt one block using this order:

~~~text
state = plaintext XOR K0

for round_number = 1 through rounds:
    state = substitute(state, sbox=sbox)
    state = permute(state)
    state = state XOR Kround_number

return state
~~~

The permutation is included in every round, including the final round. This
function never pads its input.

### `decrypt_block`

~~~python
def decrypt_block(
    key: bytes,
    ciphertext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...
~~~

Use the same expanded keys in reverse order. For each key from `Krounds` down
to `K1`, XOR the key, apply `inverse_permute`, and then apply
`inverse_substitute`. Finally XOR `K0`.

For all valid inputs:

~~~python
decrypt_block(
    key,
    encrypt_block(key, plaintext, sbox=sbox, rounds=rounds),
    sbox=sbox,
    rounds=rounds,
) == plaintext
~~~

## SeedSafe challenge

After completing `educrypto.spn`, read `challenge/README.md` and review the
provided service source. Then create `src/educrypto/attacks/week02.py` and
implement:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

`solve` must communicate with the SeedSafe server at the supplied `base_url`
and return its exact startup secret as a string. It must not start its own
server or assume a particular hostname or port.

## Running the feedback

### macOS and Linux

Run the cipher feedback without the web challenge:

~~~bash
python3 -m pytest -q course/week02 -m "not attack" -s
~~~

Run only the challenge feedback:

~~~bash
python3 -m pytest -q course/week02 -m "attack" -s
~~~

Run all Week 2 feedback:

~~~bash
python3 -m pytest -q course/week02 -s
~~~

### Windows PowerShell

From the course-material repository root, use the Windows Python launcher to
run the same feedback commands.

Run the cipher feedback without the web challenge:

~~~powershell
py -m pytest -q course/week02 -m "not attack" -s
~~~

Run only the challenge feedback:

~~~powershell
py -m pytest -q course/week02 -m "attack" -s
~~~

Run all Week 2 feedback:

~~~powershell
py -m pytest -q course/week02 -s
~~~
