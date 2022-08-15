"""
Usage:
- Point the encrypt() function to any target oracle, returning the ciphertext
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from base64 import b64decode
from time import sleep
from tqdm import tqdm
import itertools

SECRET_STRING = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
KEY = get_random_bytes(16)
PREFIX = get_random_bytes(randint(1, 100))  # Prefix length is random every time the script starts

ALPHABET = list(b" {}_Ee3Aa@4RrIi1Oo0Tt7NnSs25$LlCcUuDdPpMmHhGg6BbFfYyWwKkVvXxZzJjQq89-,.!?'\"\n\r#%&()*+/\\:;<=>[]^`|~")  # Most common
ALPHABET.extend(c for c in range(256) if c not in ALPHABET)  # Add rest of bytes


def pad(s, n):
    pad_length = n - len(s) % n
    return s + bytes([pad_length])*pad_length

def encrypt(plaintext):
    """Encrypt data and return ciphertext. Point this to the target oracle"""
    sleep(0.001)
    plaintext = PREFIX + plaintext + SECRET_STRING
    
    cipher = AES.new(KEY, AES.MODE_ECB)

    return cipher.encrypt(pad(plaintext, 16))

# Attack

def split_blocks(data, block_size):
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])
        
    return blocks

def count_diff(l1, l2):
    """"Count the number of different elements in l1 and l2"""
    return sum(i1 != i2 for i1, i2 in zip(l1, l2))

def first_diff(l1, l2):
    """Go through l1 and l2 until a difference occurs"""
    for i, (i1, i2) in enumerate(zip(l1, l2)):
        if i1 != i2:
            return i

def find_block_size():
    start = len(encrypt(b'A'))
    for i in tqdm(itertools.count(2), leave=False):
        length = len(encrypt(b'A'*i))
        
        if length > start:
            return length - start
        

def crack_letter(start, cracked, block_size, input_block):
    block_n = len(cracked) // block_size + input_block
    
    goal = encrypt(start)[block_size*block_n:block_size*(block_n+1)]
    
    for i in tqdm(ALPHABET, position=2, leave=False):
        data = encrypt(start + cracked + bytes([i]))
        block = data[block_size*block_n:block_size*(block_n+1)]
        if block == goal:
            return i

def attack():
    print("Finding block length...")
    block_size = find_block_size()
    print(f"= {block_size}")
    
    print("Finding block offset...")
    for i in tqdm(range(block_size), leave=False):
        # Send 2 different blocks of full block_size
        a = split_blocks(encrypt(b'A'*i + b'a'*block_size), block_size)
        b = split_blocks(encrypt(b'A'*i + b'b'*block_size), block_size)
        if count_diff(a, b) == 1:  # If only 1 block is affected/different, we know that it lined up with the block_size
            break
    
    padding = b'A'*i  # In future encryptions, we need to add this padding to align the block_size
    input_block = first_diff(a, b)  # Find the block number where the change occurred (where our input is)
    print(f"= {input_block}*{block_size} - {len(padding)}")
    
    print("Cracking suffix...")
    suffix_length = (len(split_blocks(encrypt(padding), block_size)) - input_block) * block_size
    
    plaintext = b''
    for i in tqdm(range(suffix_length), position=1, leave=False):  # Progress bar may mess up some printing when suffix is long
        start = padding + b"A"*(block_size-(len(plaintext)%block_size)-1)
        new_byte = crack_letter(start, plaintext, block_size, input_block)
        if new_byte is not None:  # If not found
            plaintext += bytes([new_byte])
            tqdm.write(repr(plaintext), end="\r")
        else:
            break
    
    print()  # Final newline after \r
    return plaintext


attack()
