Q: Briefly describe the main vulnerability in the challenge and how it causes the leakage of the secret.
A: The main issue in the application is the usage of a bad SBOX in SPN. The junior programmer uses a linear SBOX, which causes the output bits of the block cipher to be a linear combination of the input bits. Since the stamp is still known and unchanged from week1, that gives us a known-plaintext scenario. Knowing the input that leads to an output, we can follow through the SPN path by treating the key as hidden variables. That gives us many linear equations, and we can solve for the secret key by Gaussian Elimination.


Q: What SBOX would you suggest using for SPN? Would it fix the security issue?
A: 

It is rather difficult to design a good SBOX. Many important criteria are needed for it to be secure.

Algebraic

The first criterion for a good SBOX is that it must not be a linear function; moreover, it should be a function of high algebraic degree.

Because each output bit is a function of the input bits, i.e.

An output bit = F(input)

We must make sure that F is not just nonlinear; it must also be a high-degree function.

F(x1, x2, x3, x4) = x1* x2 + x2 * x3 + x1* x2 * x3 *x4

Then, by repeating the SPN for many rounds, the output bits will be a high-degree function of the input, which will make solving the equation system much harder.

Linear Cryptanalysis

Sometimes, even if the SBOX is a high-degree function, it can be close to a linear function. In other words, there exists a linear function that approximates the SBOX.

An example of this is 

F(x1, x2, x3, x4) = x1 + x2 * x3 *x4

The simple function F'(x) = x1 approximates the value of F, because, most of the time, the term x2 * x3 * x4 is 0

There is a family of attack call Linear Cryptanalysis that exploits this structure in the S-box to perform key recovery.

Therefore, in the design of an SBOX, it must not be easily approximated by a linear function.

Differential Cryptanalysis

The other important criterion is that it must not be vulnerable to differential cryptanalysis. Though this is not in the scope of the course, it is good to know about the existence of this attack. 

Others

There are some other required properties that we did not mention, like no fixed point, no bad algebraic structure, etc.




For this application, it is better to just use the AES S-box and further increase the number of rounds. That would prevent most of the attacks in the literature.


