# Week 4 — Message integrity and MACs

Tasks:

1. Build two message authentication codes from the Week 2 SPN and Week 3
   block-cipher machinery.
2. Win the EUF-CMA forgery game once.

Create the implementation files in your own library repository, not in this
course-material repository. The public declarations are also available in
`api.pyi`. Complete the MAC API before starting the challenge.


## Using CBC as MAC

The Week 2 SPN supplies a pseudorandom permutation on one 16-byte block. The
Week 3 CBC recurrence extends the domain to longer length inputs. 
With a
fixed zero starting value and a fixed input length, the final CBC chaining
value can be treated as a pseudorandom-function output and used as a tag.

Allowing variable-length inputs requires additional care: the two constructions
below (CMAC, PFMAC) prevent the length-extension problem in different ways.

## Common rules

Create `src/educrypto/mac.py`.

- The SPN block and key size is 16 bytes.
- Callers provide the S-box and positive round count used by every block.
- All chaining starts from the all-zero 16-byte block. There is no random IV
  and no IV is returned with a tag.
- Messages are PKCS#7-padded with `educrypto.modes.pkcs7_pad`, including empty
  and already aligned messages.
- Use the existing Week 2 and Week 3 implementations rather than
  reimplementing the SPN, XOR helper, or padding rules.
- A generated tag is always exactly 16 bytes.
- Functions return new values and must not modify their inputs.
- Except for the tag passed to a verification function, the feedback supplies
  correctly typed and correctly sized inputs. Defensive validation is not part
  of the public feedback.
- Verification returns `False` for every incorrect tag, including a tag whose
  length is not 16 bytes.

## Course CMAC

~~~python
def cmac(
    key: bytes,
    message: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...

def verify_cmac(
    key: bytes,
    message: bytes,
    tag: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bool:
    ...
~~~

The CMAC key contains exactly 32 bytes. Split it into two independent parts:

~~~text
K_enc  = key[0:16]
K_last = key[16:32]
~~~

PKCS#7-pad the message `M`, suppose there are `n` blocks, process all blocks before the last one with regular zero-IV CBC. For the final block, also XOR the second half of the key:

~~~text
C[0]   = SPN_encrypt(K_enc, M[0]) 
C[i]   = SPN_encrypt(K_enc, M[i] XOR C[i - 1])    for 1 <= i < n-2
C[n-1] = SPN_encrypt(K_enc, M[n - 1] XOR C[n - 2] XOR K_last)
tag    = C[n-1]
~~~


Only the final block is returned. Intermediate chaining values are not part of
the tag.

Note that the CMAC defined here is slightly different from NIST CMAC standard

## Prefix-free MAC (PFMAC)

~~~python
def pfmac(
    key: bytes,
    message: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bytes:
    ...

def verify_pfmac(
    key: bytes,
    message: bytes,
    tag: bytes,
    *,
    sbox: bytes,
    rounds: int,
) -> bool:
    ...
~~~

PFMAC uses one 16-byte SPN key. First PKCS#7-pad the message and count the
number of padded message blocks:

~~~text
padded = PKCS7(message)
count  = len(padded) / 16
L      = unsigned_128_big_endian(count)
~~~

`L` is a complete 16-byte block. Authenticate the following block sequence
using regular CBC with an all-zero IV:

~~~text
L || padded
~~~

Equivalently, because `L` is already aligned, you may call the Week 3 CBC
encryption function on `L || message` with a zero IV and take the last
ciphertext block. Do not add a second layer of padding.

Examples of the encoded count:

- An empty message pads to one message block, so `L` encodes `1`.
- A 15-byte message pads to one message block, so `L` encodes `1`.
- A 16-byte message receives a complete padding block, so `L` encodes `2`.
- A 32-byte message receives a complete padding block, so `L` encodes `3`.

Only the final CBC ciphertext block is the PFMAC tag.

~~~text
C   = SPN_ENCRYPT(K_enc, L || padded)
tag = last ciphertext block of C
~~~

## EUF-CMA challenge

The challenge is an existential-unforgeability-under-chosen-message-attack
game. The Server creates a fresh secret key for each game instance. You may make any
number of authentication-oracle queries and receive the tag of each chosen
message. To win the game, submit a valid tag for a message that was never sent
to the oracle under the current key.

Every well-formed forgery attempt ends the current cryptographic instance. A
valid fresh forgery immediately wins the game and reveals the secret.
An invalid forgery or a forgery of a previously queried message starts another
attempt with a fresh key. A manual reset also changes the key and clears the
current oracle history.

Messages may contain from 0 through 4096 bytes. The oracle is deterministic
within an instance, and repeated oracle queries are allowed.

Create `src/educrypto/attacks/week04.py` and implement:

~~~python
def solve(base_url: str) -> str:
    ...
~~~

Given the URL of a running service, produce one successful EUF-CMA forgery and
return the exact startup secret. Do not start a server or assume a fixed
hostname or port. See `challenge/README.md` for the complete game rules and
HTTP API.

## Running the feedback

### macOS and Linux

Run the MAC feedback without the web challenge attack:

~~~bash
python3 -m pytest -q course/week04 -m "not attack" -s
~~~

Run only the challenge feedback:

~~~bash
python3 -m pytest -q course/week04 -m "attack" -s
~~~

Run all Week 4 feedback:

~~~bash
python3 -m pytest -q course/week04 -s
~~~

### Windows PowerShell

From the course-material repository root, use the Windows Python launcher to
run the same feedback commands.

Run the MAC feedback without the web challenge attack:

~~~powershell
py -m pytest -q course/week04 -m "not attack" -s
~~~

Run only the challenge feedback:

~~~powershell
py -m pytest -q course/week04 -m "attack" -s
~~~

Run all Week 4 feedback:

~~~powershell
py -m pytest -q course/week04 -s
~~~
