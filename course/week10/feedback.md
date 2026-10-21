Q: Briefly describe your solution to win the EUF-CMA game
A: 
Query for two signatures to get 

s1 = k + (r1)x mod q 
s2 = k + 10 + (r2)x mod q

We can then recover x by solving the equation system

s2 - 10 - s1 = (r2 - r1)x mod q

which implies

x = (r2 - r1)^{-1} * (s2 - 10 - s1) mod q

Now that we recover the private key x, we can forge signature easily. 


Q: Schnorr signature comes from the Fiat-Shamir transform of the "Proof of Knowledge" scheme for the discrete logarithm. For security, it necessarily requires the hash function to be ideal (Acts like a random oracle, and not just collision resistance).

Consider the following variant of Schnorr signature where the Hash function H is changed to

H(x) = bytes_to_int(x) mod q

Suppose that you are only allow to sign/verify message of exactly 256 bit length.

State whether this scheme is EUF-CMA secure
- If you think it is not secure, design an adversary that breaks the EUF-CMA security
- If you think it is secure, justify

A:
It is not EUF-CMA secure. When r is not random, this means that the prover can cheat. The prover can produce a valid signature even when the prover does not know x

Adversary works as follow:

Choose k = 1
R = g^k = g^1 = 0
Choose m = 0^256

Then r = H(R || M) = H(0) = 0

s = k + xr = k + 0 = k

Return (k, 0) as a valid signature for M = 0^256.
The adversary can succesfully sign a message without even querying the oracle