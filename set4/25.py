from Crypto.Cipher import AES
from base64 import b64decode

BLOCK_SIZE = 16
KEY = b'\xca\xdd\x93\xb2\x18\xdc\xcc\xfa\xea\xcfem\xac\x00\xa9n"\x02\xb8\xee\x86/\x87i\xb9H\xf3\xc3O\xf3Qw'

with open("set4/25.txt") as f:
    data = [b64decode(s) for s in f.readlines() if s]


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

def edit(ciphertext, key, offset, newtext):
    plaintext = ctr_mode(ciphertext, key)
    
    if offset+len(newtext) <= len(plaintext):
        edited = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
    else:
        raise ValueError("edited text does not fit in plaintext")
    
    return ctr_mode(edited, key)

ciphertext = ctr_mode(data[0], KEY)

# Attack

def get_length():
    i = 0
    while True:
        try:
            edit(ciphertext, KEY, 0, b"A"*i)
        except ValueError:
            return i-1
        
        i += 1

def attack():
    max_length = get_length()
    out = edit(ciphertext, KEY, 0, b"A"*max_length)
    
    key_stream = byte_xor(out, b"A"*max_length)
    plaintext = byte_xor(ciphertext, key_stream)
    
    return plaintext


print(attack())
