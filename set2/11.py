from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

def pad(s, n):
    pad_length = n - len(s) % n
    if pad_length == n:  # Don't pad unnecessarily 
        pad_length = 0
    
    return s + bytes([pad_length])*pad_length

def get_aes_key():
    return get_random_bytes(16)

def random_encrypt(data):
    data = get_random_bytes(randint(5, 10)) + data + get_random_bytes(randint(5, 10))
    key = get_aes_key()
    
    if randint(0, 2) == 0:  # 50% chance
        cipher = AES.new(key, AES.MODE_ECB)
        print("Used ECB")
    else:
        cipher = AES.new(key, AES.MODE_CBC)
        print("Used CBC")
        
    return cipher.encrypt(pad(data, 16))

encrypted = random_encrypt(b"Hello World!"*100)

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

    
print("Detected", detect_encryption(encrypted))
