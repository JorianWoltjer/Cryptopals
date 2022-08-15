s = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

def xor(s, k):
    result = b""
    
    for i, c in enumerate(s):
        result += bytes([ord(c) ^ ord(k[i % len(k)])])
        
    return result

print(xor(s, "ICE").hex())
