from struct import pack, unpack

KEY = b"very secret key"

def sha1(data, registers=[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0], length=None):
    """ Returns the SHA1 sum as a 40-character hex string """
    
    h0, h1, h2, h3, h4 = registers
    
    if length is None:
        length = len(data)

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    # After the data, append a '1' bit, then pad data to a multiple of 64 bytes
    # (512 bits).  The last 64 bits must contain the length of the original
    # string in bits, so leave room for that (adding a whole padding block if
    # necessary).
    padding = b"\x80" + b"\x00" * (55 - length % 64)
    if length % 64 > 55:
        padding += b"\x00" * (64 + 55 - length % 64)
    padded_data = data + padding + pack('>Q', 8 * length)

    thunks = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]
    for thunk in thunks:
        w = list(unpack('>16L', thunk)) + [0] * 64
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(0, 80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = rol(a, 5) + f + e + k + w[i] & 0xffffffff, \
                            a, rol(b, 30), c, d

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    # print(f'{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}')
    return pack(">I", h0)+pack(">I", h1)+pack(">I", h2)+pack(">I", h3)+pack(">I", h4)


def validate(message, hash):
    return sha1(KEY + message) == hash

def check(message, hash):
    return message.endswith(b";admin=true") and validate(message, hash)


# Attack

def get_padding(data_length):
    padding = b"\x80" + b"\x00" * (55 - data_length % 64)
    if data_length % 64 > 55:
        padding += b"\x00" * (64 + 55 - data_length % 64)
    
    return padding + pack('>Q', 8 * data_length)

def split_registers(hash, size=32//8):
    registers = []
    for i in range(0, len(hash), size):
        registers.append(int.from_bytes(hash[i:i+size], 'big'))
        
    return registers

data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
valid = sha1(KEY + data)  # Valid starting hash

for i in range(100):  # Try key lengths
    glue_padding = get_padding(i + len(data))
    prev_registers = split_registers(valid)
    append = b";admin=true"
    full_length = i + len(data) + len(glue_padding) + len(append)
    # Create new hash starting with registers of valid hash
    new = sha1(append, registers=prev_registers, length=full_length)
    
    payload = data + glue_padding + append
    if check(payload, new):  # If passed validation and admin is true
        print(payload)
        print("Real", sha1(KEY + payload).hex())
        print("Fake", new.hex())
        break
