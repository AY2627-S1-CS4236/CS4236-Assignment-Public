Q: Briefly describe your solution to win the CPA game
A: 
Because the generator g is a random number h raised to the power (p-1)/q_small, (i.e g = h^{(p-1)/q_small})

Then for all value x, we have g^{q_small} = 1, which implies g^x = g^(x + q_small)

This means that there are only q_small (2^15) many distinct values of g^x even when x is randomly chosen from p.


To win the cpa game, send in two integers, message 1 and 2

Upon receiving a ciphertext from the server, we loop through all values of g^a from a = 0 to a = q_small, and one of them will be the shared g^{xy}. Check if the ciphertext is exactly g^{a}, if so, then the message is 1; otherwise, the message is 2.


Q: Suppose we have an ElGamal scheme where the prime is a safe random prime p = 2q+1 that is of size ~ 2^1028, and g is also chosen with order q

Define n = round(log_2(p)) - 1

We define the message space to be {0, 1}^n, and the encryption maps the message m to an integer by interpreting its bit string in base 2.

State whether this scheme is CPA secure
- If you think it is not secure, justify
- If you think it is secure, justify

A:
It is not CPA secure,

Because ElGamal has its ciphertext be c = m * g^{xy} mod p

If m is 0, then c will always be 0.

One can win the cpa game by just sending one message as a zero-byte message "\x00...\x00" and the other message as "\x00...\x01"

In ElGamal, we must ensure that the message will never be mapped to 0 mod p.

Note that the correctness issue presented in the tutorial where "\x00\x01" and "\x01" both maps to 1 is not a problem here.
This is because the message space is a fixed length byte {0,1}^n, only exactly n bit "\x00...\x01" is a valid message. Anything byte length shorter/longer than n is not a valid message.