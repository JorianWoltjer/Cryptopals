from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode

SECRET_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
KEY = get_random_bytes(16)

def pad(s, n):
    pad_length = n - len(s) % n
    if pad_length == n:  # Don't pad unnecessarily 
        pad_length = 0
    
    return s + bytes([pad_length])*pad_length

def encrypt(data):
    data = data + b64decode(SECRET_STRING)
    
    cipher = AES.new(KEY, AES.MODE_ECB)
        
    return cipher.encrypt(pad(data, 16))

# Attack

def get_block_size():
    start = len(encrypt(b'A'))
    i = 2
    while True:
        length = len(encrypt(b'A'*i))
        
        if length > start:
            return length - start
        
        i += 1


def has_duplicates(arr):
    seen = {}

    for x in arr:
        if x not in seen:
            seen[x] = 1
        else:
            return True
    
    return False

def detect_encryption(encrypted):
    blocks = []
    for i in range(0, len(encrypted), 16):  # Every 16 bytes
        blocks.append(encrypted[i:i+16])
        
    if has_duplicates(blocks):
        return 'ECB'
    else:
        return 'CBC'

assert get_block_size() == 16
assert detect_encryption(encrypt(b'A'*100)) == 'ECB'

def crack_letter(start, cracked, block_size):
    block_n = len(cracked) // block_size
    
    book = {}
    for i in range(256):
        data = encrypt(start + cracked + bytes([i]))
        block = data[block_size*block_n:block_size*(block_n+1)]
        book[block] = i
        
    block = encrypt(start)[block_size*block_n:block_size*(block_n+1)]
    
    return book[block]

def attack():
    block_size = get_block_size()

    cracked = b''
    while True:
        start = b"A"*(block_size-(len(cracked)%block_size)-1)
        try:
            cracked += bytes([crack_letter(start, cracked, block_size)])
        except KeyError:
            return cracked

print(attack().decode())
