# otp.py


def encrypt(pad: bytes, plaintext: bytes, offset: int = 0) -> bytes:
    """
    Encrypt plaintext using a key pad.

    If the pad is shorter than the plaintext (or offset exceeds pad length),
    it restarts/wraps from the beginning of the pad.
    """
    return b''


def decrypt(pad: bytes, ciphertext: bytes, offset: int = 0) -> bytes:
    """
    Decrypt ciphertext using a key pad.

    OTP decryption is the same operation as encryption.
    If the pad is shorter than the ciphertext (or offset exceeds pad length),
    it restarts/wraps from the beginning of the pad.
    """
    return b''