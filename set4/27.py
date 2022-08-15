from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import re

KEY = b"YELLOW SUBMARINE"
# KEY = get_random_bytes(16)
IV = KEY


def pad(s, n):
    pad_length = n - len(s) % n
    return s + bytes([pad_length])*pad_length

def unpad(s):
    padding = s[-1]
    for c in s[-padding:]:
        if c != padding:
            raise Exception("Invalid padding")

    return s[:-padding]

def encrypt(s):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    return cipher.encrypt(pad(s, 16))

def verify_ascii(s):
    for c in s:
        if c > 127:
            raise ValueError(f"Too high ascii value for string: {repr(s)}")

def decrypt(encrypted):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(encrypted)
    
    verify_ascii(plaintext)
    
    return unpad(plaintext)

# Attack

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def split_blocks(data, block_size=16):
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])
        
    return blocks


encrypted = encrypt(b"https://cryptopals.com/sets/4/challenges/27")
payload = split_blocks(encrypted)
payload = payload[0] + b'\x00'*16 + payload[0]

try:
    decrypt(payload)
except ValueError as e:
    plaintext = re.findall(r"^Too high ascii value for string: b[\"'](.*)[\"']$", str(e))[0]
    plaintext = bytes(plaintext, 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')
    blocks = split_blocks(plaintext)
    print(blocks)
    
    iv = byte_xor(blocks[0], blocks[2])
    print(iv)
