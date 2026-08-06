# Week 1 — Integer encoding and XOR

Create:

~~~text
src/educrypto/encoding.py
~~~

Implement these public functions.

## int_to_bytes

~~~python
int_to_bytes(value: int, length: int | None = None) -> bytes
~~~

- Encode an unsigned integer in big-endian order.
- Negative values raise ValueError.
- With length=None, use the shortest representation; zero is b"\x00".
- An explicit length must be positive.
- Raise ValueError if the integer does not fit the requested length.
- Do not mutate any input.

Example:

~~~python
int_to_bytes(0x1234) == b"\x12\x34"
int_to_bytes(1, 4) == b"\x00\x00\x00\x01"
~~~

## bytes_to_int

~~~python
bytes_to_int(data: bytes) -> int
~~~

- Decode unsigned big-endian bytes.
- The empty byte string represents zero.
- Non-bytes input raises TypeError.

## xor_bytes

~~~python
xor_bytes(left: bytes, right: bytes) -> bytes
~~~

- Inputs must be bytes with equal lengths.
- A type mismatch raises TypeError.
- A length mismatch raises ValueError.
- Return a new bytes object.

Run:

~~~bash
python -m pytest -q course/week01
~~~

