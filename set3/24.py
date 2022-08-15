from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes
import struct

SEED = 4242  # 16 bit

w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 1812433253

class Twister(object):
    
    def __init__(self, seed):
        self.MT = [0] * n  # Without seed, all 0's
        self.index = n + 1  # Makes sure twist at start
        self.lower_mask = (1 << r) - 1
        self.upper_mask = ~self.lower_mask & (1 << w) - 1
        
        self.set_seed(seed)
    
    def set_seed(self, seed):
        # Fill self.MT with seed first, then iterate over rest of array
        self.MT[0] = seed  # Seed not actually in MT, gets scrambled later in twist()
        for i in range(1, n):
            temp = f * (self.MT[i-1] ^ (self.MT[i-1] >> (w-2))) + i
            self.MT[i] = temp & (1 << w) - 1

    def extract_number(self):
        if self.index >= n:  # If end of array, twist
            self.twist()
            self.index = 0

        y = self.MT[self.index]  # Real internal state
        # print(y)
        y = y ^ (y >> u)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)

        self.index += 1  # Increment for next number
        return y & (1 << w) - 1  # Return interal state after bitmixing
    
    def twist(self):
        for i in range(n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % n] & self.lower_mask)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ a
            self.MT[i] = self.MT[(i + m) % n] ^ xA
            


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def keystream(twister):
    while True:
        out = twister.extract_number()
        yield from struct.pack(">I", out)

def encrypt(plaintext, seed):
    twister = Twister(seed)
    return byte_xor(plaintext, keystream(twister))

def generate(plaintext, seed):
    prefix_len = randint(2, 20)
    prefix = get_random_bytes(prefix_len)
    return encrypt(prefix + plaintext, seed)

    
# Attack

out = generate(b"A"*14, SEED)

# Crack 16 bit seed
for seed in range(2**16):
    attempt = encrypt(out, seed)
    if attempt.endswith(b"A"*14):
        print(seed)
        break
