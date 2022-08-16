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

def pad(s, block_size=16):  # PKCS#7 padding
    pad_length = block_size - len(s) % block_size
    return s + bytes([pad_length])*pad_length

def unpad(s):
    padding_byte = s[-1]  # Get last byte
    for c in s[-padding_byte:]:  # Check last n bytes
        if c != padding_byte:  # If not the same
            raise Exception("Invalid padding")

    return s[:-padding_byte]  # If valid, return without padding bytes

def get_random_ciphertext():
    secrets = [
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
    
    data = b64decode(random.choice(secrets))  # Chooses random from secrets
    
    # ! Returns IV and data, otherwise first block can't be decrypted
    return IV + cipher.encrypt(pad(data))

def validate_padding(ciphertext):
    """Decrypts the ciphertext and validates if the padding is correct. Point this to the target oracle"""
    sleep(0.001)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    data = cipher.decrypt(ciphertext)
    # print(split_blocks(data))  # To see the attack/debugging
    
    try:
        unpad(data)
    except Exception:
        return False
    else:
        return True

# Attack

def split_blocks(data, block_size=16):
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])
    
    return blocks

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def crack_block(blocks, plaintext_so_far=b''):
    plaintext = b''
    intermediate = b''
    flipped_bits = b''
    for i in tqdm(range(1, 16+1), position=2, leave=False, desc="Current block"):
        # Reorder list to make the original ciphertext byte at this position last
        possible_bytes = list(range(blocks[0][16-i]+1, 256)) + list(range(0, blocks[0][16-i]+1))
        for byte in tqdm(possible_bytes, position=3, leave=False, desc="Current byte"):  # Brute-force
            # Submit: Block before i, brute-force byte, flip needed bits in padding, original last block
            changed = blocks[0][:16-i] + bytes([byte]) + flipped_bits + blocks[1]
            if validate_padding(changed):  # Also valid if \x02\x02
                # Now we know:
                intermediate = bytes([byte ^ i]) + intermediate  # Get difference
                plaintext = bytes([byte ^ i ^ blocks[0][16-i]]) + plaintext  # Remove known byte to be left with plaintext
                tqdm.write(repr(plaintext_so_far + plaintext), end="\r")
                break
        
        # For next iteration:
        goal = bytes([i+1])*i  # \x03\x03, to make brute-force of \x03 valid
        flipped_bits = byte_xor(goal, intermediate)  # XOR needed to flip bits into correct values
    
    return plaintext

def attack(ciphertext):
    blocks = split_blocks(ciphertext)

    plaintext = b''
    for i in tqdm(range(len(blocks)-1), position=1, leave=False, desc="Total"):  # Brute-force one block at a time
        plaintext += crack_block(blocks[i:i+2], plaintext_so_far=plaintext)
    
    print()  # Final newline after \r
    return plaintext


ciphertext = get_random_ciphertext()
attack(ciphertext)
