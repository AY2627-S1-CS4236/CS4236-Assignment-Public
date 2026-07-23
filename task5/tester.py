# tester.py - Task 5 Test Runner (AES-ECB PRG based OTP)

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.test_harness import run_ipc_test_suite
from otp import decrypt, encrypt


def test_otp_encryption_decryption(
    sample_text: bytes = b"Hello, One-Time Pad with AES-ECB PRG!",
    sample_seed: bytes = b"SecretSeed123456",
) -> bool:
    decrypted = decrypt(sample_seed, encrypt(sample_seed, sample_text))
    if decrypted == sample_text:
        print("[PASS] ✔ Test Case OTP Encryption/Decryption: decrypt(seed, encrypt(seed, x)) restores x!")
        return True
    print("[FAIL] ✖ Test Case OTP Encryption/Decryption: decrypt(seed, encrypt(seed, x)) failed!")
    return False


def test_otp_double_encryption(
    sample_text: bytes = b"Hello, One-Time Pad with AES-ECB PRG!",
    sample_seed: bytes = b"SecretSeed123456",
) -> bool:
    double_encrypted = encrypt(sample_seed, encrypt(sample_seed, sample_text))
    if double_encrypted == sample_text:
        print("[PASS] ✔ Test Case OTP Double-Encryption: encrypt(seed, encrypt(seed, x)) restores original x!")
        return True
    print("[FAIL] ✖ Test Case OTP Double-Encryption: encrypt(seed, encrypt(seed, x)) did not restore x!")
    return False


def test_otp_double_decryption(
    sample_text: bytes = b"Hello, One-Time Pad with AES-ECB PRG!",
    sample_seed: bytes = b"SecretSeed123456",
) -> bool:
    double_decrypted = decrypt(sample_seed, decrypt(sample_seed, sample_text))
    if double_decrypted == sample_text:
        print("[PASS] ✔ Test Case OTP Double-Decryption: decrypt(seed, decrypt(seed, x)) restores original x!")
        return True
    print("[FAIL] ✖ Test Case OTP Double-Decryption: decrypt(seed, decrypt(seed, x)) did not restore x!")
    return False


def test_otp_seed_sensitivity(
    sample_text: bytes = b"Hello, One-Time Pad with AES-ECB PRG!",
    sample_seed: bytes = b"SecretSeed123456",
    alt_seed: bytes = b"DifferentSeed456",
) -> bool:
    c1 = encrypt(sample_seed, sample_text)
    c2 = encrypt(alt_seed, sample_text)
    if c1 != c2:
        print("[PASS] ✔ Test Case OTP Seed Sensitivity: different seeds produce different ciphertexts!")
        return True
    print("[FAIL] ✖ Test Case OTP Seed Sensitivity: different seeds produced identical ciphertext!")
    return False


def test_otp_offset_stream(
    sample_text: bytes = b"Hello, One-Time Pad with AES-ECB PRG!",
    sample_seed: bytes = b"SecretSeed123456",
) -> bool:
    c_part1 = encrypt(sample_seed, sample_text[:10], offset=0)
    c_part2 = encrypt(sample_seed, sample_text[10:], offset=10)
    c_full = encrypt(sample_seed, sample_text, offset=0)
    if c_part1 + c_part2 == c_full:
        print("[PASS] ✔ Test Case OTP Offset Stream: chunked encryption with offsets matches full encryption!")
        return True
    print("[FAIL] ✖ Test Case OTP Offset Stream: chunked encryption with offsets did not match full encryption!")
    return False


def run_otp_algebraic_tests() -> bool:
    print("\n" + "=" * 70)
    print("[UNIT TEST] Testing OTP Algebraic Properties (AES-ECB PRG)...")
    print("=" * 70)

    tests = [
        test_otp_encryption_decryption,
        test_otp_double_encryption,
        test_otp_double_decryption,
        test_otp_seed_sensitivity,
        test_otp_offset_stream,
    ]

    results = [test() for test in tests]
    return all(results)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="OTP IPC Test Runner (Task 5 - AES-ECB PRG)"
    )
    parser.add_argument(
        "--generate-key",
        action="store_true",
        default=False,
        help="Run keygen.py to generate a new key file before testing (default: False)",
    )
    parser.add_argument(
        "--key-file",
        default="key.bin",
        help="Path to the key file to use (default: key.bin)",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=16,
        help="Size of key seed to generate if --generate-key is set (default: 16)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="Number of automated test rounds before interactive mode (default: 3)",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        default=False,
        help="Skip interactive mode after automated rounds",
    )

    args = parser.parse_args()
    task_dir = Path(__file__).resolve().parent

    alg_passed = run_otp_algebraic_tests()
    run_ipc_test_suite(args, task_dir=task_dir, alg_passed=alg_passed)


if __name__ == "__main__":
    main()
