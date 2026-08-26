# Week 3 — Block cipher modes

Tasks:

1. Build ECB, CBC, and CTR modes from the Week 2 SPN block cipher.
2. Win 30 consecutive rounds of the restricted CPA (R-CPA) game.

Create the implementation files in your own library repository, not in this
course-material repository. The public declarations are also available in
`api.pyi`. Complete the mode API before starting the challenge because the
challenge server imports your implementation.

## Common rules

Create `src/educrypto/modes.py`. Every mode must call the existing
`educrypto.spn.encrypt_block` or `decrypt_block` implementation rather than
reimplementing the SPN.

- The SPN block and key size is 16 bytes.
- Callers provide the S-box and positive round count used by every block.
- Callers provide correctly sized IVs and complete ciphertext blocks.
- Functions return new `bytes` values and must not modify their inputs.
- IVs are separate inputs. Do not prepend an IV to returned ciphertext.
- ECB and CBC encryption apply PKCS#7 padding, including to empty or already
  aligned plaintexts. CTR does not use padding.
- The mode API only needs to support valid inputs; no input validation or error
  handling is required.

## PKCS#7 padding

ECB and CBC use PKCS#7 padding with a 16-byte block size. Let `n` be the number
of padding bytes required, where `n` is always between 1 and 16 inclusive.
Append `n` copies of the byte whose value is `n`.

~~~python
def pkcs7_pad(data: bytes) -> bytes:
    ...

def pkcs7_unpad(padded_data: bytes) -> bytes:
    ...
~~~

- A 13-byte plaintext receives three `b"\x03"` bytes.
- An aligned plaintext receives a complete block of sixteen `b"\x10"` bytes.
- An empty plaintext encrypts as one complete padding block.
- `pkcs7_unpad` removes the number of padding bytes indicated by the final
  byte. Its input is always valid PKCS#7-padded data.

ECB and CBC must use these public padding functions.

## Electronic Codebook (ECB)

~~~python
def encrypt_ecb(
    key: bytes,
    plaintext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...

def decrypt_ecb(
    key: bytes,
    ciphertext: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...
~~~

PKCS#7-pad the plaintext and encrypt every block independently with the same
key and SPN configuration. Decryption independently reverses each block and
then removes the padding.

## Cipher Block Chaining (CBC)

~~~python
def encrypt_cbc(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...

def decrypt_cbc(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...
~~~

The caller supplies a 16-byte CBC IV. Encrypt each
padded block with:

~~~text
# For first block
C[0] = SPN_encrypt(key, P[0] XOR IV)

# For the rest of the block
C[i] = SPN_encrypt(key, P[i] XOR C[i - 1])
~~~

Decrypt with the inverse operation:

~~~text
# For first block
P[0] = SPN_decrypt(key, C[0]) XOR IV

# For the rest of the block
P[i] = SPN_decrypt(key, C[i]) XOR C[i - 1]
~~~

## Counter mode (CTR)

~~~python
def encrypt_ctr(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...

def decrypt_ctr(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...
~~~

The caller supplies an 8-byte CTR IV. Encode the counter as an unsigned 8-byte
big-endian integer, starting at zero, and concatenate it after the IV. For each
data block:

~~~text
stream[i] = SPN_encrypt(key, IV || unsigned_64_big_endian(i))
C[i] = P[i] XOR stream[i]
~~~

Concrete example 
~~~text
stream[0] = SPN_encrypt(key, IV || 0x0000000000000000)
stream[1] = SPN_encrypt(key, IV || 0x0000000000000001)
stream[2] = SPN_encrypt(key, IV || 0x0000000000000002)
...
stream[15] = SPN_encrypt(key, IV || 0x000000000000000F)


C[i] = P[i] XOR stream[i]
~~~

CTR does not use padding. XOR only the available bytes of the final
keystream block, so ciphertext always has exactly the same length as its input.
Encryption and decryption perform the same transformation.

## R-CPA challenge

The challenge wraps the CBC implementation above in a restricted
chosen-plaintext game. At the start of each game, the server creates a fresh
key and IV. That pair is reused for every pre-challenge query, challenge
encryption, and post-challenge query within the game. A guess ends the game and
the next game starts with a new key and IV. The oracle and challenge return the
IV separately from the PKCS#7-padded CBC ciphertext.

The Reset button abandons the current game and starts another with a new key,
new IV, and empty message history. It does not change the current win streak.

An exact plaintext may be
used by the encryption oracle or as a challenge candidate, but never both
during the same game instance. 

For example, if "apple" is used as the challenge message, player cannot query the encryption of "apple". Similarly, if the encryption of "apple" was queried before, the message "apple" cannot be used as one of the challenge message.

The difference between a normal CPA game from the lecture and this R-CPA game is that normal CPA allows the query of any message, include the challenge message. 
R-CPA game on the other hand does not. Therefore, you can consider R-CPA is a model where the adversary is weaker. 

In general, proving security against a stronger adversary is more desirable. 
However, in this challenge, we will show that CBC with fix IV is not even secure against this weaker adversary.

This application misuse does not add another public mode API.

Create `src/educrypto/attacks/week03.py` and implement:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Given the URL of a running service, win 30 consecutive R-CPA rounds and return
the exact startup secret. Do not start a server or assume a fixed hostname or
port. See `challenge/README.md` for the complete game rules and HTTP API.

## Running the feedback

### macOS and Linux

Run the cipher feedback without the web challenge:

~~~bash
python3 -m pytest -q course/week03 -m "not attack" -s
~~~

Run only the challenge feedback:

~~~bash
python3 -m pytest -q course/week03 -m "attack" -s
~~~

Run all Week 3 feedback:

~~~bash
python3 -m pytest -q course/week03 -s
~~~

### Windows PowerShell

From the course-material repository root, use the Windows Python launcher to
run the same feedback commands.

Run the cipher feedback without the web challenge:

~~~powershell
py -m pytest -q course/week03 -m "not attack" -s
~~~

Run only the challenge feedback:

~~~powershell
py -m pytest -q course/week03 -m "attack" -s
~~~

Run all Week 3 feedback:

~~~powershell
py -m pytest -q course/week03 -s
~~~
