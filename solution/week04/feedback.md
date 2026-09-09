Q: Briefly describe your solution to win the EUF-CMA game using PFMAC with 2 blocks output as tag
A: There are many ways to attack this.

A simple way to attack is to query the oracle a plaintext of the following form

P = some random 16 byte plaintext || "A" * 15 

Padded(P) = some random 16 byte plaintext || "A" * 15 + "0x01"

Once you found P1 and P2 such that 

P1 = B_1 || "A" * 15 + "0x01"

P2 = B_2 || "A" * 15 + "0x01"

For some B_1, B_2 that is different

This gives you Enc(B_1), Enc(B_2), Enc(("A" * 15 + "0x01") Xor Enc(B_1)), Enc(("A" * 15 + "0x01") Xor Enc(B_2))

Suppose that the last byte of Enc(B_1) and Enc(B_2) is both "00" (If this doesn't happen, then keep trying different B until you find two that has this property)

Then ("A" * 15 + "0x01") Xor Enc(B_1) Xor Enc(B_2) would also has the last byte being "0x01"

So the forgery can then be

Plaintext = B_1 || ("A" * 15) Xor Enc(B_1)[:-1] Xor Enc(B_2)[:-1]

Padded Plaintext =  B_1 || ("A" * 15) Xor Enc(B_1)[:-1] Xor Enc(B_2)[:-1] + "0x01"

Tag = Enc(B_1) || Enc(("A" * 15 + "0x01") Xor Enc(B_2))

This will then be a valid forgery



Q: Suppose now the underlying scheme changes from PFMAC to CMAC (as defined in the homework)

And similar to before, the last two block outputs are provided.

If the message is too short (less than 16 bytes) and only contains one output block c, then just return c || c

State whether it is possible for an efficient adversary to win the EUF-CMA game.

- If you think it is possible, design an adversary that wins this game.

- If you think it is not possible, justify your claim.

A:

Assuming that the block cipher is secure, it is not possible to design an efficient adversary that wins the game. We can justify this as follows:

The reason is that because in CMAC, the last block is shifted with a hidden key. So for every query, what we know is only
the ciphertext block is enc(p_last xor k_last xor c_secondlast). And since we assume the block cipher is secure, no efficient adversary can derive information about the input, hence also know nothing about k_last. Without knowing k_last, it is certainly not possible to construct a new valid tag.