Q: LWE security is very sensitive to the parameters.

Describe a CPA attack on the LWE Public key encryption scheme we implememted when m <= n

A:

When m <= n,

The matrix A is has more columns than rows, 

In the public key encryption, we generate a random r and provided r^TA

Transpose r^TA to get A^Tr.

A^T has m columns and n rows, m <= n (it is a tall matrix)

Because A^T is full rank with high probability, we can treat A^Tr as a overspecified linear equations with secret r and has no error at all! We can easily recover the r using Gaussian Elimination

Once r is recovered, distinguish message is easy.