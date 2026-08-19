# These two functions are implemented for you as an example

def int_to_bytes(value: int) -> bytes:
    byte_length = max((value.bit_length() + 7) // 8, 1)
    return value.to_bytes(byte_length)

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data)

def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes([x^y for x,y in zip(left, right)])
