Practical Homework 1 Canvas Questions and Answer 

Q: Briefly describe the main vulnerability in the challenge and how it causes the leakage of the secret.
A: The vulnerability in the system is OTP reuse. A short seed is used as the OTP and when the length shorter than the plaintext, the key is repeated. Furthermore, because the server also encrypts a known "stamp" at the end of message, that helps us to exactly derive the seed which enables us to fully decrypt any message.

Q: Briefly describe how you would patch the security vulnerability in this application?
A: A simple patch would be to generate a seed as long as the plaintext. This would however be rather inefficient because the seed is not short anymore.