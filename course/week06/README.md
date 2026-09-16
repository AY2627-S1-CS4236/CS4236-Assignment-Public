# Week 6 — Authenticated encryption with associated data

This week has two parts:

1. Combine the Week 3 CTR mode, Week 4 CMAC, and Week 5
   Merkle–Damgård hash into two authenticated-encryption constructions.
2. Analyze an IND-CCA2 game whose encrypt-then-MAC construction uses a custom
   iterated hash.

Create implementation files in your own library repository, not in this
course-material repository. The public declarations are also available in
`api.pyi`. Complete the AEAD API before starting the challenge.

## Authenticated encryption and associated data

Encryption hides a plaintext, while a message authentication code detects
changes. Authenticated encryption with associated data (AEAD) provides both.
Associated data is authenticated but remains visible. A network protocol might
use it for a fixed-size record header that must be checked but must not be
encrypted.

Create `src/educrypto/aead.py`. Reuse these earlier functions:

- `educrypto.modes.encrypt_ctr` and `decrypt_ctr` from Week 3;
- `educrypto.mac.cmac` and `verify_cmac` from Week 4; and
- `educrypto.hashing.merkle_damgard` and `AES_SBOX` from Week 5.

Do not copy their internal recurrences into the new module.

## Common rules

- The complete AEAD key is 48 bytes: `K_enc || K_mac`.
- `K_enc = key[0:16]` is the Week 3 CTR key.
- `K_mac = key[16:48]` is the Week 4 course-CMAC key.
- The caller supplies an 8-byte CTR IV.
- Associated data may contain 0 through 15 bytes.
- Plaintexts may have any length, including zero. CTR applies no padding.
- Inputs and outputs are immutable `bytes` values.
- `sbox` is keyword-only and defaults to the Week 5 `AES_SBOX`.
- `rounds` is a required keyword-only argument and is used for every SPN call.
- Feedback supplies correctly typed values with correct key, IV, and associated
  data sizes. Defensive input validation is not required.
- A decryption function returns the plaintext after successful authentication
  and `None` when authentication fails.

The two encryption functions return the IV and associated data supplied by the
caller. This keeps every transmitted component explicit and avoids hiding a
serialization format inside the cryptographic functions.

### Associated-data padding

Pad associated data to exactly one 16-byte block before using it in either
construction. Because the input contains at most 15 bytes, there is always
space for the first padding bit:

~~~text
padded_AD = associated_data || 0x80 || zero bytes
~~~

Append the minimum number of zero bytes needed to make `padded_AD` 16 bytes.
The byte `0x80` represents one `1` bit followed by seven `0` bits, so this is
byte-aligned `10*` padding. It is not PKCS#7 padding.

| Associated-data length | Padding suffix |
| ---: | --- |
| 0 | `80` followed by 15 zero bytes |
| 1 | `80` followed by 14 zero bytes |
| 14 | `80 00` |
| 15 | `80` |

Return the original associated data, not `padded_AD`, from encryption. The
receiver reconstructs the padded block from that original value.

The `0x80` marker binds the original associated-data length, even when the data
ends in zero bytes. In MTE, CMAC's mandatory padding binds the length of the
complete MAC input and therefore the plaintext length. In ETM, the Week 5
Merkle–Damgård length field binds the length of the padded AD and ciphertext.

## MAC then encrypt (MTE)

~~~python
def encrypt_mte(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> tuple[bytes, bytes, bytes]:
    ...

def decrypt_mte(
    key: bytes,
    ciphertext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes | None:
    ...
~~~

MTE authenticates the visible context and plaintext before encryption:

~~~text
padded_AD  = PAD10*(associated_data)
tag        = CMAC(K_mac, IV || padded_AD || plaintext)
combined   = tag || plaintext
ciphertext = CTR_encrypt(K_enc, combined, IV)
return (IV, associated_data, ciphertext)
~~~

The tag is exactly 16 bytes, so it occupies the first encrypted block. CTR
counter zero encrypts this tag. Counter one begins the plaintext when the
plaintext is non-empty.

For decryption:

~~~text
combined     = CTR_decrypt(K_enc, ciphertext, IV)
received_tag = combined[0:16]
plaintext    = combined[16:]
padded_AD    = PAD10*(associated_data)
expected_tag = CMAC(K_mac, IV || padded_AD || plaintext)
~~~

Return `plaintext` only when `verify_cmac` accepts `received_tag`. Otherwise,
return `None`. Even an empty plaintext has a tag, so its MTE ciphertext is 16
bytes long. In general:

~~~text
len(MTE ciphertext) = 16 + len(plaintext)
~~~

## Encrypt then MAC (ETM)

~~~python
def encrypt_etm(
    key: bytes,
    plaintext: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> tuple[bytes, bytes, bytes, bytes]:
    ...

def decrypt_etm(
    key: bytes,
    ciphertext: bytes,
    tag: bytes,
    *,
    iv: bytes,
    associated_data: bytes,
    sbox: bytes = AES_SBOX,
    rounds: int,
) -> bytes | None:
    ...
~~~

ETM encrypts first. It hashes the associated data, IV, and ciphertext, then
uses a separate CMAC key to authenticate the digest:

~~~text
ciphertext = CTR_encrypt(K_enc, plaintext, IV)
padded_AD  = PAD10*(associated_data)
digest     = MerkleDamgard(padded_AD || IV || ciphertext)
tag        = CMAC(K_mac, digest)
return (IV, associated_data, ciphertext, tag)
~~~

CTR counter zero encrypts the first plaintext bytes. No counter value is
reserved for the tag. The tag is returned as a separate fourth component and
is not part of the ciphertext.

ETM decryption must calculate the digest and verify the tag before decrypting:

~~~text
digest = MerkleDamgard(PAD10*(associated_data) || IV || ciphertext)
if VerifyCMAC(K_mac, digest, tag) is false:
    return None
return CTR_decrypt(K_enc, ciphertext, IV)
~~~

The Merkle–Damgård padding records the length of its complete input. The
separate associated-data padding makes `padded_AD` one fixed block, so the
boundaries before the fixed-size IV and ciphertext are unambiguous. Because the
IV is inside the digest, CMAC authenticates only the 16-byte digest.

## Worked layout example

Suppose the plaintext is 20 bytes. MTE authenticates all 20 bytes, prepends the
16-byte tag, and passes 36 bytes to CTR:

~~~text
counter 0 encrypts tag[0:16]
counter 1 encrypts plaintext[0:16]
counter 2 encrypts plaintext[16:20]
~~~

ETM passes only the 20-byte plaintext to CTR:

~~~text
counter 0 encrypts plaintext[0:16]
counter 1 encrypts plaintext[16:20]
~~~

It then hashes `padded_AD || IV || ciphertext` and returns a separate 16-byte
tag over that digest.

## IND-CCA2 challenge

The challenge service uses the ETM layout with the block recurrence below in
place of the Week 5 Merkle–Damgård construction. Associated data contains at
most 15 bytes and is `10*`-padded to one block before CMAC authenticates it. A
fresh 48-byte key is created for every game round, and every encryption receives
a fresh random IV.

The Player may:

1. ask the encryption oracle to encrypt chosen plaintext and associated data;
2. submit two equal-length messages and one associated-data value for a
   challenge;
3. ask the decryption oracle to authenticate and decrypt chosen AEAD tuples;
4. guess which challenge message the Server encrypted.

The exact challenge tuple may not be submitted to the decryption oracle. Any
different tuple is permitted. This is the CCA restriction: the Player cannot
win by simply asking the Server to decrypt the challenge unchanged.

### Challenge hash

Interpret every 16-byte ciphertext block as an unsigned big-endian integer.
Start with `H = 0` and process the ciphertext blocks in order:

~~~text
H = (7 * H + block) mod 2^128
~~~

If the ciphertext ends with a partial block, append zero bytes inside the hash
calculation until that block contains 16 bytes. These zero bytes are not part
of CTR encryption or the returned ciphertext.

The challenge tag is:

~~~text
padded_AD = PAD10*(associated_data)
digest    = challenge_hash(ciphertext)
tag       = CMAC(K_mac, IV || padded_AD || digest)
~~~

Win 30 consecutive rounds to receive the Server's
startup secret.

Create `src/educrypto/attacks/week06.py`:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Use the supplied URL. Do not start a server, read its environment, assume a
fixed port, or guess the secret. See `challenge/README.md` for the complete
game lifecycle and HTTP API.

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
python3 -m pip install -r course/week06/challenge/requirements.txt

# Library only
python3 -m pytest -q course/week06 -m "not attack" -s

# Challenge attack only
python3 -m pytest -q course/week06 -m "attack" -s

# All Week 6 feedback
python3 -m pytest -q course/week06 -s
~~~

### Windows PowerShell

From your library repository:

~~~powershell
py -m pip install -e .
~~~

From the course-material repository:

~~~powershell
py -m pip install pytest
py -m pip install -r course/week06/challenge/requirements.txt

# Library only
py -m pytest -q course/week06 -m "not attack" -s

# Challenge attack only
py -m pytest -q course/week06 -m "attack" -s

# All Week 6 feedback
py -m pytest -q course/week06 -s
~~~

The attack test starts a temporary local Server and makes at least one
challenge, decryption, and guess request for each of 30 rounds.
