# solver.py - Task 3 Attack Script (Repeating Key OTP Attack with Offset)

import argparse
import re
import socket


def recv_until(sock: socket.socket, target: bytes) -> str:
    data = b""
    while target not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace")


def solve_task3(host: str, port: int) -> bool:
    print(f"[ATTACK] Connecting to server at {host}:{port}...")

    with socket.create_connection((host, port), timeout=5) as sock:
        recv_until(sock, b"Choice > ")

        # Step 1: Request Encrypted Challenge Message (Option 1) at offset 0
        print("[ATTACK] Requesting encrypted challenge message (Option 1)...")
        sock.sendall(b"1\n")
        resp1 = recv_until(sock, b"Choice > ")

        match_msg = re.search(r"Encrypted Challenge Message \(hex\):\s*([0-9a-fA-F]+)", resp1)
        if not match_msg:
            print("[ATTACK ERROR] Failed to parse encrypted message!")
            return False

        enc_msg_hex = match_msg.group(1)
        enc_msg_bytes = bytes.fromhex(enc_msg_hex)
        msg_len = len(enc_msg_bytes)
        print(f"[ATTACK] Encrypted challenge message hex: {enc_msg_hex} (Length: {msg_len} bytes)")

        # Step 2: Query Oracle with null bytes matching message length at offset msg_len
        print(f"[ATTACK] Querying encryption oracle with {msg_len} null bytes...")
        sock.sendall(b"2\n")
        recv_until(sock, b"Enter message (hex) > ")

        null_payload = "00" * msg_len
        sock.sendall(f"{null_payload}\n".encode("utf-8"))
        resp2 = recv_until(sock, b"Choice > ")

        match_key = re.search(r"Ciphertext \(hex\):\s*([0-9a-fA-F]+)", resp2)
        if not match_key:
            print("[ATTACK ERROR] Failed to parse oracle response!")
            return False

        recovered_key = bytes.fromhex(match_key.group(1))
        print(f"[ATTACK] Recovered Key stream hex: {recovered_key.hex()}")

        # Step 3: Decrypt secret message
        decrypted_msg_bytes = bytes(c ^ k for c, k in zip(enc_msg_bytes, recovered_key))
        decrypted_msg = decrypted_msg_bytes.decode("utf-8", errors="replace")
        print(f"[ATTACK SUCCESS] Decrypted Message: \"{decrypted_msg}\"")

        # Step 4: Submit decrypted message to server (Option 3)
        print("[ATTACK] Submitting decrypted message to server (Option 3)...")
        sock.sendall(b"3\n")
        recv_until(sock, b"Enter decrypted message > ")
        sock.sendall(f"{decrypted_msg}\n".encode("utf-8"))

        final_resp = recv_until(sock, b"Choice > ")
        print(f"[SERVER OUTPUT] {final_resp.strip()}")

        return "[SUCCESS]" in final_resp


def main():
    parser = argparse.ArgumentParser(description="Task 3 Attack Script")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9003, help="Target port (default: 9003)")
    args = parser.parse_args()

    success = solve_task3(args.host, args.port)
    if success:
        print("[RESULT] Task 3 Attack Executed Successfully!")
    else:
        print("[RESULT] Task 3 Attack Failed!")


if __name__ == "__main__":
    main()
