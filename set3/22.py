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
        self.MT[0] = seed
        for i in range(1, n):
            temp = f * (self.MT[i-1] ^ (self.MT[i-1] >> (w-2))) + i
            self.MT[i] = temp & (1 << w) - 1

    def extract_number(self):
        if self.index >= n:  # If end of array, twist
            self.twist()
            self.index = 0

        y = self.MT[self.index]  # Real internal state
        y = y ^ ((y >> u) & d)
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


def generate():
    seed = int(time.time())
    twister = Twister(seed)
    print(seed)
    return twister.extract_number()
    
# print(generate())

# Attack

def crack(n):
    seed = int(time.time())  # Start at current time
    
    while True:
        twister = Twister(seed)  # Reset index and set seed
        if twister.extract_number() == n:
            return seed
        
        seed -= 1  # Go back 1 second
        

seed = crack(382197005)
print(f"{seed=} -> {datetime.fromtimestamp(seed)}")
