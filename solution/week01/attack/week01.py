# You should implement your attack here
import requests
from educrypto.otp import decrypt
from educrypto.encoding import xor_bytes

COMPANY_NAME = "SeedSafe"

def _stamp(created_at: str) -> bytes:
    return f"\n\n{COMPANY_NAME} {created_at}".encode("utf-8")

def solve(base_url: str) -> str:
    data = requests.get(base_url + "/api/v1/backups").json()
    payload = data['backups'][0]
    ciphertext = bytes.fromhex(payload['ciphertext_hex'])
    created_at = payload['created_at']
    known_text = _stamp(created_at)
    key = xor_bytes(ciphertext[-len(known_text):], known_text)
    key_part = key[-16:]
    # Find the right offset
    for i in range(16):
        # Rotate the key
        test_key = key_part[i:] + key_part[:i]
        if f'\n\n{COMPANY_NAME}'.encode() in decrypt(test_key, ciphertext):
            return decrypt(test_key, ciphertext).split(b"\n")[0].decode()
    return ''