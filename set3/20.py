from Crypto.Cipher import AES
from base64 import b64decode
from string import ascii_letters, digits

BLOCK_SIZE = 16
KEY = b"YELLOW SUBMARINE"

ALPHABET = ascii_letters + " ,.!?'/"

with open("set3/20.txt") as f:
    data = f.readlines()

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

def ctr_mode(s, key):
    return byte_xor(s, ctr_keystream(key, nonce=0))  # Fixed nonce to 0

def score_text(s):
    return sum(bytes([c]) in bytes(ALPHABET, "utf-8") for c in s)

encryped = [ctr_mode(b64decode(s), KEY) for s in data]

longest = 0
for e in encryped:
    if len(e) > longest:
        longest = len(e)
        
key = b""
for i in range(longest):  # Go over every letter in ciphertexts
    best_score = 0
    best_letter = None
    for letter in range(256):
        plaintext = [ciphertext[i] ^ letter for ciphertext in encryped if i < len(ciphertext)]
        score = score_text(plaintext) / len(plaintext)
        
        if score > best_score:
            best_score = score
            best_letter = letter
    
    key += bytes([best_letter])

    
for e in encryped:
    print(byte_xor(key, e))
