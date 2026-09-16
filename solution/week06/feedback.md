Q: Briefly describe your solution to win the IND-CCA2 game
A:

Send in two messages 

p1 = b"A" * 16
p2 = b"B" * 16
associated_data = b"C" * 15

Receive the ciphertext c,

Send in c || to_int(c[-16:]) * (-6) for decryption (with the same associated_data)

Then check the decryption of the message and see whether it is "A" * 16 in the first block of "B" * 16 in the first block

Q: Consider the ETM scheme you implemented,

Instead of padding the associated_data = AD, the AD is added directly to the front of ciphertext

digest = MerkleDamgard(AD || ciphertext)

State whether this construction is IND-CCA2 secure

- If you think it is not secure, justify
- If you think it is secure, justify

A:

It is not secure, to win the CCA game, send in two message

p1 = b"A" * 16
p2 = b"B" * 16
associated_data = b"C" * 2

obtain the challenge ciphertext with (IV, associated_data, ciphertext, tag)

then query the oracle to decrypt with 

(same iv, "C", "C" || ciphertext, tag)

This is a valid forgery, because 

tag = MerkleDamgard("C" || "C" || ciphertext) = MerkleDamgard("CC" || ciphertext)

Since in IND-CCA2 game, the decryption oracle rejects only the exact challenge tuple.
the decryption oracle will also accept this ciphertext because the associated_data is different.

The decrypted text would be ("C" || ciphertext) xor (keystream). Recover the keystream and xor with ciphertext to see if the ciphertext is an encryption of "A" * 16 or "B" * 16

