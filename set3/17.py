"""
Resources:
- https://www.youtube.com/watch?v=QhuUvrrGJbE  (Code)
- https://samsclass.info/141/proj/p14pad.htm  (Visual explanation)

Usage:
- Point the validate_padding() function to any target oracle, returning True if the padding is valid and False if the padding is invalid
- Then run attack() on any ciphertext to decrypt it using the oracle defined earlier
    - To get the whole plaintext (including first block) the ciphertext needs to be prepended with the IV
"""

from time import sleep
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
from base64 import b64decode
from tqdm import tqdm

KEY = get_random_bytes(16)
IV = b"\x00"*16

def pad(s, block_size=16):
    pad_length = block_size - len(s) % block_size
    return s + bytes([pad_length])*pad_length

def unpad(s):
    padding = s[-1]
    for c in s[-padding:]:
        if c != padding:
            raise Exception("Invalid padding")

    return s[:-padding]

def get_random_ciphertext():
    strings = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", 
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", 
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", 
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", 
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", 
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", 
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", 
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", 
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", 
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93", 
    ]
    
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    data = b64decode(random.choice(strings))
    # data = b64decode(strings[0])
    
    # ! Returns IV and data, otherwise first block can't be decrypted
    return IV + cipher.encrypt(pad(data))

def validate_padding(ciphertext):
    """Decrypts the ciphertext and validates if the padding is correct. Point this to the target oracle"""
    sleep(0.001)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    data = cipher.decrypt(ciphertext)
    # print(split_blocks(data))
    
    try:
        unpad(data)
    except Exception:
        return False
    else:
        return True

def test_decrypt(encrypted):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    data = cipher.decrypt(encrypted)
    
    return data


# Attack

def split_blocks(data, block_size=16):
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])
        
    return blocks

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def flip_bit(s, i):
    binary = list(bin(int.from_bytes(s, 'big'))[2:])
    binary[i] = "0" if binary[i] == "1" else "1"
    print(len(binary))
    
    return bitstring_to_bytes(''.join(binary))

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def crack_block(blocks, cracked_plaintext=b''):
    plaintext = b''
    intermediate = b''
    injection = b''
    for i in tqdm(range(1, 16+1), position=2, leave=False, desc="Current block"):
        possible_bytes = list(range(blocks[0][16-i]+1, 256)) + list(range(0, blocks[0][16-i]+1))
        for byte in tqdm(possible_bytes, position=3, leave=False, desc="Current byte"):  # Test ciphertext byte last
            changed = blocks[0][:16-i] + bytes([byte]) + injection + blocks[1]
            if validate_padding(changed):  # also valid if \x02\x02
                intermediate = bytes([byte ^ i]) + intermediate  # Reverse
                plaintext = bytes([byte ^ i ^ blocks[0][16-i]]) + plaintext
                tqdm.write(repr(cracked_plaintext + plaintext), end="\r")
                break
        
        goal = bytes([i+1])*i  # b'\x03\x03'
        injection = byte_xor(goal, intermediate)
        changed = blocks[0][:16-i] + injection + blocks[0][16:]
    
    return plaintext

def attack(ciphertext):
    blocks = split_blocks(ciphertext)

    plaintext = b''
    for i in tqdm(range(len(blocks)-1), position=1, leave=False, desc="Total"):
        plaintext += crack_block(blocks[i:i+2], cracked_plaintext=plaintext)
    
    print()  # Final newline after \r
    return plaintext


ciphertext = get_random_ciphertext()
attack(ciphertext)
