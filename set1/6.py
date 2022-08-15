import base64
from string import ascii_letters, digits
import re

from numpy.lib.function_base import average

ALPHABET = ascii_letters + digits + ' .,!?'

def hamming(s1, s2):
    """
    Calculates the hamming distance between two strings (binary distance)
    """
    if len(s1) != len(s2):
        raise ValueError("Strings must be of equal length")

    if isinstance(s1, str):
        s1 = s1.encode()
    if isinstance(s2, str):
        s2 = s2.encode()

    total = 0
    for i in range(len(s1)):
        b1 = bin(s1[i])[2:].zfill(8)
        b2 = bin(s2[i])[2:].zfill(8)
        
        for j in range(len(b1)):
            if b1[j] != b2[j]:
                total += 1
        
    return total

# print(hamming("this is a test", b"wokka wokka!!!"))

def score_keysize(keysize, data):
    num_chunks = len(data) // keysize
    
    distances = []
    for i in range(num_chunks-1):
        chunk1 = data[i*keysize:(i+1)*keysize]
        chunk2 = data[(i+1)*keysize:(i+2)*keysize]
        
        distances.append(hamming(chunk1, chunk2) / keysize)
        
    return average(distances)


def get_keysize(data):
    best = 2**32
    best_keysize = None

    for keysize in range(2, 40):
        score = score_keysize(keysize, data)
        
        if score < best:
            best = score
            best_keysize = keysize
            
    return best_keysize

def xor(s, k):
    result = b""
    
    for i, c in enumerate(s):
        result += bytes([c ^ k[i % len(k)]])
        
    return result

def score_text(s):
    return sum(c in bytes(ALPHABET, "utf-8") for c in s)


with open("set1/6.txt", "r") as f:
    data = f.read().replace("\n", "")
    data = base64.b64decode(data)
    

keysize = get_keysize(data)
print(f"{keysize=}")

transpose = [b''] * keysize
for i in range(0, len(data), keysize):
    block = data[i:i+keysize]
    for i in range(len(block)):
        transpose[i] += bytes([block[i]])

full_key = b''
for s in transpose:
    best_score = -1
    best_key = None
    
    for key in range(256):
        d = xor(s, bytes([key]))
        
        this_score = score_text(d)
        if this_score > best_score:
            best_score = this_score
            best_key = key
    
    full_key += bytes([best_key])

print(f"{full_key}")

m = xor(data, full_key)

print(m.decode())
