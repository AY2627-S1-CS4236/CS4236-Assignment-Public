# Week 4 — PKCS#7 padding and AES-ECB

Create:

~~~text
src/educrypto/symmetric/padding.py
src/educrypto/symmetric/ecb.py
~~~

## PKCS#7

~~~python
pkcs7_pad(message: bytes, block_size: int) -> bytes
pkcs7_unpad(padded: bytes, block_size: int) -> bytes
~~~

- block_size must be an integer from 1 through 255.
- Padding is always added, including to an aligned or empty message.
- Every padding byte equals the number of bytes added.
- Malformed padding raises ValueError.
- Non-bytes messages raise TypeError.

## AES-ECB

~~~python
encrypt(key: bytes, plaintext: bytes) -> bytes
decrypt(key: bytes, ciphertext: bytes) -> bytes
~~~

- Accept 16, 24, or 32-byte AES keys.
- Input data must be block aligned.
- Empty input returns empty bytes.
- Invalid key or data lengths raise ValueError.
- This layer does not add or remove padding.
- ECB is implemented for study and later composition, not recommended usage.

Run:

~~~bash
python -m pytest -q course/week04
~~~

