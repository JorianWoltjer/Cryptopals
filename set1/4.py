import re
from string import ascii_letters, digits

ALPHABET = ascii_letters + digits + ' .,!?'

def xor(s, k):
    result = b""
    
    for i, c in enumerate(s):
        result += bytes([c ^ k[i % len(k)]])
        
    return result

def score(s):
    return sum(c in bytes(ALPHABET, "utf-8") for c in s)


with open("set1/4.txt", "r") as f:
    lines = f.readlines()
    
    best_score = -1
    best_key = None
    best_d = None
    
    for line_i, line in enumerate(lines):
        line = bytes.fromhex(line.strip())
        
        for key in range(256):
            d = xor(line, bytes([key]))
            
            this_score = score(d)
            if this_score > best_score:
                best_score = this_score
                best_key = key
                best_d = d
    
print(best_d, best_key)
