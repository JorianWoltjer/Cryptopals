from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(16)
IV = b'\x00'*16


def pad(s, n):
    pad_length = n - len(s) % n
    return s + bytes([pad_length])*pad_length

def unpad(s):
    padding = s[-1]
    for c in s[-padding:]:
        if c != padding:
            raise Exception("Invalid padding")

    return s[:-padding]

def escape(s):
    return s.replace(b"%", b"%25").replace(b";", b"%3B").replace(b"=", b"%3D")

def user_input(s):
    s = escape(s)
    data = b"comment1=cooking%20MCs;userdata=" + s + b";comment2=%20like%20a%20pound%20of%20bacon"
    
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    return cipher.encrypt(pad(data, 16))

def check(encrypted):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    s = cipher.decrypt(encrypted)
    
    return b";admin=true;" in s

def test_decrypt(encrypted):  # May not be used for attack
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    return cipher.decrypt(encrypted)

# Attack

def split_blocks(data, block_size=16):
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])
        
    return blocks

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def flip_bit(s, i):
    binary = list(bin(int.from_bytes(s, 'big'))[2:])
    binary[i] = "0" if binary[i] == "1" else "1"
    
    return bitstring_to_bytes(''.join(binary))

# A = 01000001
# C = 01000011
# ; = 00111011
# : = 00111010
# = = 00111101
# < = 00111100

normal = user_input(b"A"*16 + b':admin<true')

b = 2
blocks = split_blocks(normal)
changed = blocks[b]
print(changed)
changed = flip_bit(changed, -1 + 1*8)  # [1] character = : -> ;
changed = flip_bit(changed, -1 + 7*8)  # [7] character = < -> =
print(changed)
blocks[b] = changed
payload = b''.join(blocks)

# print(split_blocks(test_decrypt(normal)))
# print(split_blocks(test_decrypt(payload)))

print(check(payload))
