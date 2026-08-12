# Week 1 — Encoding and one-time pads

Tasks:

1. Implement the library API specified below.
2. Solve the challenge in the `challenge` folder.

Create the implementation files in your own library repository, not in this
course-material repository. Complete APIs implementation before starting
the challenge because the challenge server imports your implementation.

## Feature Requests

The interface declarations are also available in `api.pyi`.

### `educrypto.encoding`

Create `src/educrypto/encoding.py` with the following public functions.

#### `int_to_bytes`

~~~python
def int_to_bytes(value: int) -> bytes:
    ...
~~~

Convert a non-negative integer to its minimal-length unsigned big-endian byte
representation.

- Do not include redundant leading zero bytes.
- Represent zero as `b"\x00"`.

Examples:

~~~python
int_to_bytes(0)       == b"\x00"
int_to_bytes(1)       == b"\x01"
int_to_bytes(0x1234)  == b"\x12\x34"
~~~

#### `bytes_to_int`

~~~python
def bytes_to_int(data: bytes) -> int:
    ...
~~~

Interpret `data` as an unsigned big-endian integer and return its value.
Leading zero bytes do not affect the result.

Examples:

~~~python
bytes_to_int(b"\x00")          == 0
bytes_to_int(b"\x01")          == 1
bytes_to_int(b"\x00\x12\x34") == 0x1234
~~~

#### `xor_bytes`

~~~python
def xor_bytes(left: bytes, right: bytes) -> bytes:
    ...
~~~

XOR corresponding bytes from `left` and `right`. The result must have the
length of the shorter input; any unmatched bytes in the longer input are
discarded. If either input is empty, return `b""`.

Examples:

~~~python
xor_bytes(b"\x0f\xaa", b"\xf0\x55") == b"\xff\xff"
xor_bytes(b"abc", b"X")              == b"9"
xor_bytes(b"", b"anything")          == b""
~~~

### `educrypto.otp`

Create `src/educrypto/otp.py` with the following public functions.

#### `encrypt`

~~~python
def encrypt(pad: bytes, plaintext: bytes) -> bytes:
    ...
~~~

XOR `plaintext` with `pad` and return the resulting ciphertext.

- If `pad` is shorter than `plaintext`, repeat the pad from the beginning until
  it is long enough.
- If `pad` is longer than `plaintext`, use only the required prefix of the pad.
- The returned ciphertext must have the same length as `plaintext`.
- A non-empty plaintext requires a non-empty pad.

#### `decrypt`

~~~python
def decrypt(pad: bytes, ciphertext: bytes) -> bytes:
    ...
~~~

Apply the same repeating-pad XOR operation to `ciphertext` and return the
plaintext. Pad repetition and truncation follow the same rules as `encrypt`.
Consequently, for valid inputs:

~~~python
decrypt(pad, encrypt(pad, plaintext)) == plaintext
~~~

The encoding and OTP functions operate on bytes. They do not perform text
encoding or decoding for the caller.

## Challenge

### `educrypto.attacks.week01`

Create `src/educrypto/attacks/week01.py` with the following public function.

#### `solve`

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Given the base URL of a running SeedSafe service, recover and return the
service's startup secret as a `str`. For example, the test may call `solve`
with a URL such as `http://127.0.0.1:54321`. The function must interact with
the running service and return the exact secret value; it must not start its
own challenge server.

See `challenge/README.md` for challenge setup and service details.

## Testing

Run all Week 1 feedback:

~~~bash
python3 -m pytest -q course/week01 -s
~~~

Run library and attack feedback separately:

~~~bash
python3 -m pytest -q course/week01 -m "not attack" -s
python3 -m pytest -q course/week01 -m "attack" -s
~~~
