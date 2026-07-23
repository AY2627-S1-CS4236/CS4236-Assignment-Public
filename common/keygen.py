# keygen.py - Key material / seed generation and loading

import os
from pathlib import Path


def generate_key(output_path: str | Path, size: int = 4096) -> Path:
    """
    Generate random key material / seed and write it to the specified output file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key_bytes = os.urandom(size)
    path.write_bytes(key_bytes)
    return path


def load_key_file(key_file: str | Path) -> bytes:
    """
    Load OTP key material / seed from a file.
    """
    path = Path(key_file)

    if not path.exists():
        raise FileNotFoundError(f"key file does not exist: {path}")

    key = path.read_bytes()

    if len(key) < 2:
        raise ValueError("key file must contain at least 2 bytes")

    return key
