# Week 5 — Hashing

This week has two parts:

1. Implement Davies–Meyer compression, Merkle–Damgård hashing, and a
   configurable sponge in your `educrypto` library.
2. Find one collision for each of two deliberately weak sponge settings. The
   Server reveals its startup secret after both targets are solved.

Create implementation files in your own library repository, not in this
course-material repository. The declarations and supplied constants are in
`api.pyi`. Complete all three hashes before the challenge, because its Server
imports your `sponge_hash`.

These are teaching constructions built from the Week 2 SPN. Using the AES
S-box does not turn that SPN into AES. Reuse your earlier SPN and XOR helper;
do not replace the assigned constructions with a cryptography package.

## Common rules

Create `src/educrypto/hashing.py`.

- Cipher keys, cipher inputs, chaining values, and sponge states are 16 bytes.
- Inputs and outputs are immutable `bytes`.
- Reuse `educrypto.spn.encrypt_block` and
  `educrypto.encoding.xor_bytes`.
- `rounds` is a required keyword-only argument and must be positive. Use it
  for every SPN call made by that function.
- `sbox` is keyword-only and defaults to `AES_SBOX`. A custom S-box follows
  the Week 2 rules: it is a 256-byte permutation of 0 through 255.
- Implement the two Week 5 padding helpers as public functions so you can
  inspect and test padded messages directly. Leave the Week 3 PKCS#7 functions
  unchanged; neither Week 5 hash uses PKCS#7.
- Work with bytes directly. Text encoding and hexadecimal conversion belong to
  the caller.

The feedback supplies correctly typed data, valid S-boxes, and positive round
counts. Your sponge must reject capacities outside `0 <= c < 16` and negative
digest lengths with `ValueError`.

## Supplied constants

Copy the complete `AES_SBOX` table and these constants from `api.pyi`:

~~~python
MD_IV: bytes = b"\xff" * 16
SPONGE_KEY: bytes = bytes(range(16))
~~~

`MD_IV` is the fixed initial chaining value for Merkle–Damgård. Its hex value
is `ffffffffffffffffffffffffffffffff`.

`SPONGE_KEY` is the sponge permutation's fixed public key. Its hex value is
`000102030405060708090a0b0c0d0e0f`. It is the same for every invocation and
does not depend on the message.

## Davies–Meyer compression

~~~python
def davies_meyer(
    data: bytes,
    *,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes:
    ...
~~~

`data` is exactly 32 bytes arranged as `H || M`:

~~~text
H = data[0:16]      previous chaining value; SPN plaintext
M = data[16:32]     one message block; SPN key

output = SPN_encrypt(key=M, plaintext=H) XOR H
~~~

`||` means byte concatenation. The final XOR is the feed-forward step.
Davies–Meyer returns exactly 16 bytes and performs no padding.

~~~python
H = bytes(range(16))
M = bytes.fromhex("00112233445566778899aabbccddeeff")
davies_meyer(H + M, rounds=10).hex()
# "aaf8580ddfb6d7b20fe012fca39b42e8"
~~~

## Merkle–Damgård hashing

~~~python
def merkle_damgard_pad(message: bytes) -> bytes:
    ...

def merkle_damgard(
    message: bytes,
    *,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes:
    ...
~~~


`merkle_damgard_pad` accepts any message length, records its original bit
length, and returns the complete padded byte string:

~~~text
message || 0x80 || zero bytes || original_bit_length
~~~

Encode `original_bit_length` as a 16-byte unsigned big-endian integer. Insert
the minimum number of zero bytes that places this length field in its own final
16-byte block and makes the complete padded value a multiple of 16 bytes.
Padding is always added.

`merkle_damgard` must call this public helper once and split its result into
16-byte blocks. The helper does not call the compression function.

| Original length | Bytes before length field | Total padded length |
| ---: | --- | ---: |
| 0 | `80` followed by 15 zero bytes | 32 bytes |
| 1 | message, `80`, then 14 zero bytes | 32 bytes |
| 15 | message, `80` | 32 bytes |
| 16 | message, `80`, then 15 zero bytes | 48 bytes |
| 17 | message, `80`, then 14 zero bytes | 48 bytes |

For a one-byte message there are 8 original bits, so the final length block
is `00000000000000000000000000000008`.

~~~python
merkle_damgard_pad(b"").hex()
# "80" followed by 62 zero hexadecimal characters

merkle_damgard_pad(b"A")[-16:].hex()
# "00000000000000000000000000000008"
~~~

Process the padded blocks in byte order:

~~~text
H[0]     = MD_IV
H[i + 1] = davies_meyer(H[i] || M[i], sbox=sbox, rounds=rounds)
digest   = H[n]
~~~

Return only the final 16-byte chaining value. Do not apply PKCS#7 or pad again
inside `davies_meyer`.

~~~python
merkle_damgard(b"", rounds=10).hex()
# "b1f4df280aa203d7652cd0ec08d764e1"

merkle_damgard(bytes(range(16)), rounds=10).hex()
# "f59a20b058c4848e680f2aed0566b273"
~~~

## Configurable sponge

~~~python
def sponge_pad(message: bytes, *, c: int) -> bytes:
    ...

def sponge_hash(
    message: bytes,
    *,
    c: int,
    digest_length: int,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes:
    ...
~~~

The 16-byte state starts as zero for every invocation. Capacity `c` and
`digest_length` are in bytes. The rate is `rate = 16 - c`. Require
`0 <= c < 16`, so the rate is between 1 and 16. The first `rate` state
bytes form the rate portion; the final `c` bytes form the capacity.

The internal permutation is the Week 2 SPN under the fixed public key:

~~~text
P(S) = SPN_encrypt(key=SPONGE_KEY, plaintext=S)
~~~

### MSB-first pad10*1

`sponge_pad` validates `c`, derives `rate = 16 - c`, and returns the message
padded to whole `rate`-byte blocks. Always add padding, including to an empty
or rate-aligned message. `sponge_hash` must use this public helper.

- If exactly one byte is needed, append `81`.
- Otherwise append `80`, enough `00` bytes, and a final `01`.

For a four-byte rate:

| Message | Padded bytes |
| --- | --- |
| empty | `80 00 00 01` |
| `aa` | `aa 80 00 01` |
| `aa bb cc` | `aa bb cc 81` |
| `aa bb cc dd` | `aa bb cc dd 80 00 00 01` |

~~~python
sponge_pad(b"", c=12).hex() == "80000001"
sponge_pad(bytes.fromhex("aabbcc"), c=12).hex() == "aabbcc81"
~~~

### Absorption

XOR each padded block into the first `rate` bytes, retain the capacity bytes,
and then apply `P`:

~~~text
state = 00...00
for each padded block B:
    state = P((state[0:rate] XOR B) || state[rate:16])
~~~

Byte 0 of the block is XORed with state byte 0. Do not reverse the bytes.

### Squeezing

After absorption, copy from the rate portion. Apply `P` between output blocks
until exactly `digest_length` bytes have been returned:

~~~text
output = state[0:rate]
state = P(state)
output = output || state[0:rate]
... stop at exactly digest_length bytes
~~~

Do not permute before the first output. Truncate a final partial block. A zero
digest length returns `b""`.

Worked example: with `c=13`, the rate is three bytes. The one-byte message
`aa` pads to `aa8001`. Starting from the zero state, XOR that block into
state bytes 0 through 2 and apply `P`. For six output bytes, emit the first
three bytes of that result, apply `P`, and append the next three bytes.

~~~python
sponge_hash(b"", c=13, digest_length=3, rounds=10).hex()
# "5dd991"

sponge_hash(b"hello", c=3, digest_length=32, rounds=10).hex()
# "bd2743566d2686663cb47aae39c67390beba138c87fd9447abb3ac2bfcddcaea"
~~~

Under identical parameters, a shorter digest is a prefix of a longer digest.

## Two-hash collision challenge

The challenge calls your sponge with the AES S-box, ten rounds, the fixed key,
and the zero initial state.

| Target | Capacity | Rate | Complete digest |
| --- | ---: | ---: | ---: |
| `hash1` | 13 bytes | 3 bytes | 3 bytes |
| `hash2` | 3 bytes | 13 bytes | 32 bytes |

For each target, submit two different decoded messages with matching complete
digests. Solve them in either order. The first accepted collision records one
win. The second completes the game and returns the exact startup secret.

Create `src/educrypto/attacks/week05.py`:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Your solver creates a game, computes and submits both collisions, and returns
the exact secret supplied by the successful second response. Use the supplied
URL. Do not start a server, read its environment, or assume a fixed host or port. See
`challenge/README.md` for the full game and HTTP API.

## Setup and feedback

Install your library in editable mode, then install the course and challenge
requirements into the same Python environment.

### macOS and Linux

From your library repository:

~~~bash
python3 -m pip install -e .
~~~

From the course-material repository:

~~~bash
python3 -m pip install pytest
python3 -m pip install -r course/week05/challenge/requirements.txt

# Library only
python3 -m pytest -q course/week05 -m "not attack" -s

# Challenge attack only
python3 -m pytest -q course/week05 -m "attack" -s

# All Week 5 feedback
python3 -m pytest -q course/week05 -s
~~~

### Windows PowerShell

From your library repository:

~~~powershell
py -m pip install -e .
~~~

From the course-material repository:

~~~powershell
py -m pip install pytest
py -m pip install -r course/week05/challenge/requirements.txt

# Library only
py -m pytest -q course/week05 -m "not attack" -s

# Challenge attack only
py -m pytest -q course/week05 -m "attack" -s

# All Week 5 feedback
py -m pytest -q course/week05 -s
~~~

The attack test performs a real collision search and can take noticeably
longer than the library tests.
