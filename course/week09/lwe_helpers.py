"""Supplied Week 09 matrix arithmetic and bit conversion.

Copy this file to src/educrypto/lwe_helpers.py in your library repository.
Matrix inputs must be nonempty, rectangular, and dimensionally compatible.
Bit packing requires a multiple of eight bits, each equal to 0 or 1.
"""


def matrix_multiply(
    left: list[list[int]],
    right: list[list[int]],
    *,
    modulus: int,
) -> list[list[int]]:
    """Return left times right, reducing each entry modulo modulus."""

    columns = transpose(right)
    return [
        [sum(a * b for a, b in zip(row, column)) % modulus for column in columns]
        for row in left
    ]


def transpose(matrix: list[list[int]]) -> list[list[int]]:
    """Return a new matrix with rows and columns interchanged."""

    return [list(column) for column in zip(*matrix)]


def bytes_to_bits(data: bytes) -> list[int]:
    """Expand bytes in order, most significant bit first within each byte."""

    return [(value >> shift) & 1 for value in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Pack groups of eight bits, most significant bit first."""

    output = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)
