# Week 5 — AES-CBC and a padding oracle

Create:

~~~text
src/educrypto/symmetric/cbc.py
~~~

Implement:

~~~python
encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes
decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes
~~~

- Accept 16, 24, or 32-byte AES keys.
- IVs are exactly 16 bytes.
- Input data must be block aligned.
- Empty input returns empty bytes.
- Invalid key, IV, or data lengths raise ValueError.
- This layer does not add or remove padding.
- Use big-endian byte conventions only where integer conversion is needed.
- Do not mutate inputs.

## Attack task

The supplied service performs correct CBC decryption and PKCS#7 unpadding but
reveals whether padding is valid. This application-level error oracle makes
plaintext recovery possible even though the primitive itself is correct.

Create:

~~~text
attacks/week05_padding_oracle.py
~~~

Implement:

~~~python
solve(host: str, port: int) -> bytes
~~~

Use PaddingOracleClient from challenge/client.py. Return the recovered unpadded
secret. The server uses a fresh key, IV, and secret each time and limits the
number of oracle queries.

Run:

~~~bash
python -m pytest -q course/week05
~~~

