# solver.py - Task 4 Attack Script (Python PRNG Stream Cipher Attack with MT19937 State Recovery & Offset Tracking)

import argparse
import random
import re
import socket


def un_shift_right_xor(val: int, shift: int) -> int:
    res = val
    for _ in range(32 // shift):
        res = val ^ (res >> shift)
    return res


def un_shift_left_xor_mask(val: int, shift: int, mask: int) -> int:
    res = val
    for _ in range(32 // shift):
        res = val ^ ((res << shift) & mask)
    return res


def untemper(y: int) -> int:
    y = un_shift_right_xor(y, 18)
    y = un_shift_left_xor_mask(y, 15, 0xefc60000)
    y = un_shift_left_xor_mask(y, 7, 0x9d2c5680)
    y = un_shift_right_xor(y, 11)
    return y


def recv_until(sock: socket.socket, target: bytes) -> str:
    data = b""
    while target not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace")


def solve_task4(host: str, port: int) -> bool:
    print(f"[ATTACK] Connecting to server at {host}:{port}...")

    with socket.create_connection((host, port), timeout=5) as sock:
        recv_until(sock, b"Choice > ")

        # Step 1: Query Oracle with 2496 null bytes at offset 0 to extract MT19937 PRNG state
        print("[ATTACK] Querying PRNG encryption oracle with 2496 null bytes at offset 0...")
        sock.sendall(b"2\n")
        recv_until(sock, b"Enter message (hex) > ")

        null_payload = "00" * 2496
        sock.sendall(f"{null_payload}\n".encode("utf-8"))
        resp1 = recv_until(sock, b"Choice > ")

        match_stream = re.search(r"Ciphertext \(hex\):\s*([0-9a-fA-F]+)", resp1)
        if not match_stream:
            print("[ATTACK ERROR] Failed to parse oracle keystream response!")
            return False

        keystream_bytes = bytes.fromhex(match_stream.group(1))
        print(f"[ATTACK] Extracted 2496 bytes of keystream at offset 0.")

        # Step 2: Untemper 624 32-bit integers and clone PRNG state at offset 2496
        print("[ATTACK] Untempering MT19937 outputs to reconstruct PRNG state at offset 2496...")
        words = [int.from_bytes(keystream_bytes[i:i+4], "little") for i in range(0, 2496, 4)]
        recovered_state = [untemper(w) for w in words]

        cloned_rng = random.Random()
        cloned_rng.setstate((3, tuple(recovered_state + [624]), None))

        # Step 3: Request Encrypted Challenge Message (Option 1) at offset 2496
        print("[ATTACK] Requesting encrypted challenge message (Option 1) at offset 2496...")
        sock.sendall(b"1\n")
        resp2 = recv_until(sock, b"Choice > ")

        match_msg = re.search(r"Encrypted Challenge Message \(hex\):\s*([0-9a-fA-F]+)", resp2)
        if not match_msg:
            print("[ATTACK ERROR] Failed to parse encrypted message!")
            return False

        enc_msg_hex = match_msg.group(1)
        enc_msg_bytes = bytes.fromhex(enc_msg_hex)
        msg_len = len(enc_msg_bytes)
        print(f"[ATTACK] Encrypted challenge message hex: {enc_msg_hex} (Length: {msg_len} bytes)")

        # Step 4: Predict keystream at offset 2496 using cloned PRNG state and decrypt message
        predicted_keystream = cloned_rng.randbytes(msg_len)
        decrypted_msg_bytes = bytes(c ^ k for c, k in zip(enc_msg_bytes, predicted_keystream))
        decrypted_msg = decrypted_msg_bytes.decode("utf-8", errors="replace")
        print(f"[ATTACK SUCCESS] Decrypted Message: \"{decrypted_msg}\"")

        # Step 5: Submit decrypted message to server (Option 3)
        print("[ATTACK] Submitting decrypted message to server (Option 3)...")
        sock.sendall(b"3\n")
        recv_until(sock, b"Enter decrypted message > ")
        sock.sendall(f"{decrypted_msg}\n".encode("utf-8"))

        final_resp = recv_until(sock, b"Choice > ")
        print(f"[SERVER OUTPUT] {final_resp.strip()}")

        return "[SUCCESS]" in final_resp


def main():
    parser = argparse.ArgumentParser(description="Task 4 Attack Script")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9004, help="Target port (default: 9004)")
    args = parser.parse_args()

    success = solve_task4(args.host, args.port)
    if success:
        print("[RESULT] Task 4 Attack Executed Successfully!")
    else:
        print("[RESULT] Task 4 Attack Failed!")


if __name__ == "__main__":
    main()
