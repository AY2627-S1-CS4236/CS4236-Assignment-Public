# keygen.py - Key material generator for Task 1

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from common.keygen import generate_key, load_key_file


def main() -> None:
    parser = argparse.ArgumentParser(description="OTP Key Generator")
    parser.add_argument(
        "--out",
        "-o",
        "--key-file",
        dest="out",
        default="key.bin",
        help="Path to output key file (default: key.bin)",
    )
    parser.add_argument(
        "--size",
        "-s",
        type=int,
        default=4096,
        help="Size of key material in bytes (default: 4096)",
    )

    args = parser.parse_args()
    key_path = generate_key(args.out, args.size)
    print(f"Generated {args.size} bytes of key material at {key_path}")


if __name__ == "__main__":
    main()
