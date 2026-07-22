# keygen.py

import argparse
import os
from pathlib import Path


def generate_key(output_path: str | Path, size: int = 4096) -> Path:
    """
    Generate random key material and write it to the specified output file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key_bytes = os.urandom(size)
    path.write_bytes(key_bytes)
    return path


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
