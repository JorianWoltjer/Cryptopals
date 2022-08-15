from Crypto.Cipher import AES
from base64 import b64decode

s = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
KEY = b"YELLOW SUBMARINE"
BLOCK_SIZE = 16


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def ctr_keystream(key, nonce):
    cipher = AES.new(key, AES.MODE_ECB)
    
    counter = 0 
    nonce_bytes = nonce.to_bytes(BLOCK_SIZE // 2, 'little')
    while True:
        counter_bytes = counter.to_bytes(BLOCK_SIZE // 2, 'little')
        yield from cipher.encrypt(nonce_bytes + counter_bytes)
        counter += 1

def ctr_mode(s, key, nonce):
    return byte_xor(s, ctr_keystream(key, nonce))

print(ctr_mode(s, KEY, nonce=0))
