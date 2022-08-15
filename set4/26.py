from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(16)
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

def ctr_mode(s, key):
    return byte_xor(s, ctr_keystream(key, nonce=0))  # Fixed nonce to 0

def escape(s):
    return s.replace(b"%", b"%25").replace(b";", b"%3B").replace(b"=", b"%3D")

def user_input(s):
    s = escape(s)
    data = b"comment1=cooking%20MCs;userdata=" + s + b";comment2=%20like%20a%20pound%20of%20bacon"
    
    return ctr_mode(data, KEY)

def check(encrypted):
    s = ctr_mode(encrypted, KEY)
    
    return b";admin=true;" in s

# Attack

def flip_bit(s, char, bit):
    new = s[char] ^ int(2**((bit-7) % 8))
    return s[:char] + bytes([new]) + s[char+1:]

start = 32
out = user_input(b":admin<true")
changed = out
changed = flip_bit(changed, start+0, -1)  # First char, last bit
changed = flip_bit(changed, start+6, -1)  # First char, last bit

print(out)
print(changed)
print(check(changed))
