import struct

KEY = b"very secret key"

WIDTH = 32
MASK = 0xFFFFFFFF

def F(x, y, z):
        return (x & y) | (~x & z)

def G(x, y, z):
    return (x & y) | (x & z) | (y & z)

def H(x, y, z):
    return x ^ y ^ z

def lrot(value, n):
    lbits, rbits = (value << n) & MASK, value >> (WIDTH - n)
    return lbits | rbits

def md4(data, registers=[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476], length=None):
    
    if length is None:
        length = len(data)+1
    
    ml = length * 8
    data += b"\x80"
    data += b"\x00" * (-(length + 8) % 64)
    data += struct.pack("<Q", ml)
    
    chunks = [data[i:i+64] for i in range(0, len(data), 64)]
    
    for chunk in chunks:
        X, h = list(struct.unpack("<16I", chunk)), registers.copy()

        # Round 1
        Xi = [3, 7, 11, 19]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = n, Xi[n % 4]
            hn = h[i] + F(h[j], h[k], h[l]) + X[K]
            h[i] = lrot(hn & MASK, S)

        # Round 2
        Xi = [3, 5, 9, 13]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = n % 4 * 4 + n // 4, Xi[n % 4]
            hn = h[i] + G(h[j], h[k], h[l]) + X[K] + 0x5A827999
            h[i] = lrot(hn & MASK, S)

        # Round 3
        Xi = [3, 9, 11, 15]
        Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for n in range(16):
            i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
            K, S = Ki[n], Xi[n % 4]
            hn = h[i] + H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
            h[i] = lrot(hn & MASK, S)

        registers = [((v + n) & MASK) for v, n in zip(registers, h)]
    
    return struct.pack("<4L", *registers)


def validate(message, hash):
    return md4(KEY + message) == hash

def check(message, hash):
    return message.endswith(b";admin=true") and validate(message, hash)


# Attack

def get_padding(data_length):
    ml = data_length * 8
    padding = b"\x80"
    padding += b"\x00" * (-(data_length + 8) % 64)
    return padding + struct.pack("<Q", ml)

def split_registers(hash, size=32//8):
    registers = []
    for i in range(0, len(hash), size):
        registers.append(int.from_bytes(hash[i:i+size], 'little'))
        
    return registers

data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
valid = md4(KEY + data)  # Valid starting hash

for i in range(100):  # Try key lengths
    glue_padding = get_padding(i + len(data))
    prev_registers = split_registers(valid)
    append = b";admin=true"
    full_length = i + len(data) + len(glue_padding) + len(append)
    # Create new hash starting with registers of valid hash
    new = md4(append, registers=prev_registers, length=full_length)
    
    payload = data + glue_padding + append
    if check(payload, new):  # If passed validation and admin is true
        print(payload)
        print("Real", md4(KEY + payload).hex())
        print("Fake", new.hex())
        break
