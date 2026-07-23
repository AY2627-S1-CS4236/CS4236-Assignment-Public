# tester.py - Task 1 Test Runner

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.test_harness import run_ipc_test_suite
from otp import decrypt, encrypt


def test_otp_self_encryption(sample_text: bytes = b"Hello, One-Time Pad!") -> bool:
    zero_bytes = b"\x00" * len(sample_text)
    res = encrypt(sample_text, sample_text)
    if res == zero_bytes:
        print("[PASS] ✔ Test Case OTP Self-Encryption: encrypt(x, x) produces all zero bytes!")
        return True
    print("[FAIL] ✖ Test Case OTP Self-Encryption: encrypt(x, x) did not produce all zero bytes!")
    return False


def test_otp_self_decryption(sample_text: bytes = b"Hello, One-Time Pad!") -> bool:
    zero_bytes = b"\x00" * len(sample_text)
    res = decrypt(sample_text, sample_text)
    if res == zero_bytes:
        print("[PASS] ✔ Test Case OTP Self-Decryption: decrypt(x, x) produces all zero bytes!")
        return True
    print("[FAIL] ✖ Test Case OTP Self-Decryption: decrypt(x, x) did not produce all zero bytes!")
    return False


def test_otp_double_encryption(
    sample_text: bytes = b"Hello, One-Time Pad!",
    sample_pad: bytes = b"SecretKeyMaterial123",
) -> bool:
    double_encrypted = encrypt(sample_pad, encrypt(sample_pad, sample_text))
    if double_encrypted == sample_text:
        print("[PASS] ✔ Test Case OTP Double-Encryption: encrypt(pad, encrypt(pad, x)) restores original x!")
        return True
    print("[FAIL] ✖ Test Case OTP Double-Encryption: encrypt(pad, encrypt(pad, x)) did not restore x!")
    return False


def test_otp_double_decryption(
    sample_text: bytes = b"Hello, One-Time Pad!",
    sample_pad: bytes = b"SecretKeyMaterial123",
) -> bool:
    double_decrypted = decrypt(sample_pad, decrypt(sample_pad, sample_text))
    if double_decrypted == sample_text:
        print("[PASS] ✔ Test Case OTP Double-Decryption: decrypt(pad, decrypt(pad, x)) restores original x!")
        return True
    print("[FAIL] ✖ Test Case OTP Double-Decryption: decrypt(pad, decrypt(pad, x)) did not restore x!")
    return False


def run_otp_algebraic_tests() -> bool:
    print("\n" + "=" * 70)
    print("[UNIT TEST] Testing OTP Algebraic Properties...")
    print("=" * 70)

    tests = [
        test_otp_self_encryption,
        test_otp_self_decryption,
        test_otp_double_encryption,
        test_otp_double_decryption,
    ]

    results = [test() for test in tests]
    return all(results)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="OTP IPC Test Runner (Task 1)"
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
        default=4096,
        help="Size of key to generate if --generate-key is set (default: 4096)",
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