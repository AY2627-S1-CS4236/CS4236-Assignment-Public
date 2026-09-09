Q: Briefly describe your solution to win the R-CPA game using CBC encryption with a fixed IV
A: Since the IV is the same throughout the game, we know the encryption of the first block is deterministic.
A simple attack would be

1) Query the encryption of b"A" * 16 and note down the ciphertext of the first block.

2) Send in a challenge messages LEFT = b"A" * 16 + b"B" * 16 and RIGHT = "B" * 32

3) Check if the first block of the challenge message matches the first block of the ciphertext of "A" * 16. If it matches, then return LEFT; otherwise RIGHT


Q: Suppose now we further weaken the adversary such that no oracle queries are allowed. 

To be more exact, this is the following sequence of the game:

1) Game start: the server generates a random key and iv

2) Adversary send server two challenge messages m0, m1

3) The server picks a challenge message at random (say mb), encrypts it and send back to the adversary

4) The adversary answers b = 0 or b = 1

Using the same cipher suite as in the challenge and assuming that the block cipher is secure,

state whether it is possible for an efficient adversary to win this game.

- If you think it is possible, design an adversary that wins this game.

- If you think it is not possible, justify your claim.

A:
Assuming that the block cipher is secure, it is not possible to design an efficient adversary that wins the game. We can justify this as follows:

Throughout the game, the adversary only receives an encryption of a single message, with a fresh random IV and a fresh random key. There is no IV reuse because the adversary is not allowed to query the oracle.

Now consider the usual CPA game for CBC mode; in that game, the adversary is allowed multiple oracle queries, but each with a random new IV. This is a game in which an adversary is less restricted compared to the new game. (Why? Because in our game the adversary only gets one message, but in a normal CPA game the adversary can arbitrarily query for any number of messages)

That means if we can construct an adversary that wins this restricted game, that adversary will also win the less restricted normal CPA game.

However, we know that CBC mode is CPA secure; if such an adversary exists, it will contradict the fact that CBC mode is CPA secure. Therefore, it is impossible to do so.


