Q: Briefly describe your solution to find a collision on the challenge server hash
A:

For the first hash, where the output is just 3 bytes. We can find a collision by hashing random messages. Due to birthday attack, with about 2^(3*8)/2 tries, a collision will show up with high probability.

For the second hash, we solve it by finding two distinct 13 bytes message p1 and p2 such that after concatenation with 3 zero bytes, the last 3 bytes is the same (i.e)

Enc(p1||"0x00" * 3)[-3:] = Enc[p2||"0x00" * 3)][-3:]

When this happens, let 

t1 = Enc(p1||"0x00" * 3)[:13]
t2 = Enc(p2||"0x00" * 3)[:13]


then hash(p1 || t1) = hash(p2 || t2)

And that is a valid collision

Q: From the lecture, we know that Davies-Meyer converts an 'ideal' block cipher to collision resistant hash function.
Roughly speaking, 'ideal' cipher here means that for every key, a random permutation p_k is chosen so that Enc(k, m) = p_k(m).
In other words, for every key, a message is mapped to a random ciphertext.

Suppose the hash function F is defined as (Following Davies-Meyer):

F(x||y) = Enc(key = y, message = x) xor x
Where Enc is any CPA-secure block cipher (not necessarily ideal).

State whether this hash in general, is collision-resistant or not.

- If you think it is not collision-resistant, justify
- If you think it is collision-resistant, justify

A:
This hash function is not collision resistant in general. Take any CPA secure encryption scheme Enc and modify it to Enc' as follows:

Enc'(k, msg) = Enc(k, msg) if k != 0
Enc'(k, msg) = msg if k = 0

Since in CPA game, the key is first randomly selected out from 2^128 possible keys (assuming 128 bit security), with a very high probability (1/2^128) the key will not be t.
Therefore, this Enc' is still CPA secure.

Essentially, we are adding a backdoor key. (and the adversary cannot do anything about it because the key is chosen by the challenger)

Now this F is not collision-resistant

We have that for all messages m, m'
F(m'||0) = F(m||0) = 0

In general, we want block cipher to be an 'ideal' cipher for it to a valid collision resistant hash function.
In practice, block ciphers like AES somewhat acts like an 'ideal' cipher, which is why we can use it to construct hash function.