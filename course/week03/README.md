# Week 3 — One-time pads and keystream reuse

Create:

~~~text
src/educrypto/symmetric/__init__.py
src/educrypto/symmetric/otp.py
~~~

Implement:

~~~python
encrypt(pad: bytes, plaintext: bytes) -> bytes
decrypt(pad: bytes, ciphertext: bytes) -> bytes
~~~

- Both inputs must be bytes.
- Pad and message must have exactly equal lengths.
- Type mismatches raise TypeError.
- Length mismatches raise ValueError.
- Neither function mutates its inputs.
- Encryption and decryption are the same XOR operation.

## Attack task

The application under challenge/ correctly calls the OTP primitive but
incorrectly reuses one pad.

Create:

~~~text
attacks/week03_keystream_reuse.py
~~~

Implement:

~~~python
solve(host: str, port: int) -> bytes
~~~

Use the supplied ReuseOracleClient. Return the recovered secret plaintext.
Do not read server internals or hardcode a secret.

Run:

~~~bash
python -m pytest -q course/week03
~~~

