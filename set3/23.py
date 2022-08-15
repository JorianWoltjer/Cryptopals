import time
from datetime import datetime

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
            

# Attack

twister = Twister(42)
# print("out", twister.extract_number())
# print("out", twister.extract_number())

# Source: https://blog.ollien.com/posts/reverse-mersenne-twister/
def undo_right_transform(value, shift):
    res = value

    for i in range(0, w, shift):
        # Work on the next shift sized portion at a time by generating a mask for it.
        portion_mask = '0' * i + '1' * shift + '0' * (w - shift - i)
        portion_mask = int(portion_mask[:w], 2)
        portion = res & portion_mask

        res ^= portion >> shift

    return res

def undo_left_transform(value, shift, mask):
    res = value
    for i in range(0, w, shift):
        # Work on the next shift sized portion at a time by generating a mask for it.
        portion_mask = '0' * (w - shift - i) + '1' * shift + '0' * i
        portion_mask = int(portion_mask, 2)
        portion = res & portion_mask

        res ^= ((portion << shift) & mask)

    return int(res)

def reverse(out):
    y = out
    y = undo_right_transform(y, l)
    y = undo_left_transform(y, t, c)
    y = undo_left_transform(y, s, b)
    y = undo_right_transform(y, u)
    
    return y


MT = []
for i in range(624):
    out = twister.extract_number()
    MT.append(reverse(out))

clone = Twister(0)
clone.MT = MT

print("Prediction", [clone.extract_number() for _ in range(10)])
print("Result    ", [twister.extract_number() for _ in range(10)])
