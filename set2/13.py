from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(16)

def escape(s):
    if isinstance(s, str):
        return s.replace("%", "%25").replace("&", "%26").replace("=", "%3D")
    
    return s

def unescape(s):
    return s.replace("%25", "%").replace("%26", "&").replace("%3D", "=")

def decode_kv(s):
    result = {}
    
    for pair in s.split("&"):
        key, value = pair.split("=")
        
        key = unescape(key)
        value = unescape(value)
        
        result[key] = value
    
    return result

def encode_kv(d):
    result = ""
    
    first = True
    for key, value in d.items():
        if not first:
            result += "&"
        
        key = escape(key)
        value = escape(value)
        
        result += f"{key}={value}"
        first = False
        
    return result

def profile_for(email):
    data = {
        "email": email,
        "uid": 10,
        "role": 'user'
    }
    
    return encode_kv(data)


def pad(s, n):
    pad_length = n - len(s) % n
    return s + bytes([pad_length])*pad_length

def unpad(s):
    padding = s[-1]
    if s[-padding:] == bytes([padding])*padding:
        return s[:-padding].decode()
    
    return padding.decode()

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_ECB)
        
    return cipher.encrypt(pad(bytes(data, "utf-8"), 16))

def decrypt(data):
    cipher = AES.new(KEY, AES.MODE_ECB)
        
    return cipher.decrypt(data)

# Accessable functions

def create_full(email):
    return encrypt(profile_for(email))

def read_full(encrypted):
    return decode_kv(unpad(decrypt(encrypted)))


# Attack

def test_input(s):
    return create_full(f"user+{s}@example.com")

def split_blocks(data, block_size):
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i+block_size])
        
    return blocks

def get_block_size():
    start = len(test_input(b'A'))
    i = 2
    while True:
        length = len(test_input(b'A'*i))
        
        if length > start:
            return length - start
        
        i += 1

def attack():
    block_size = get_block_size()
    
    # Get 'admin' block
    start = split_blocks(test_input('A'*block_size), block_size)
    for i in range(block_size):
        padding = 'A'*i+'B'+'A'*(block_size-i-1)
        
        blocks = split_blocks(test_input(padding), block_size)
        
        if blocks[1] != start[1]:
            admin_offset = i
            break
            
    admin_block = split_blocks(test_input('A'*admin_offset+pad(b'admin', block_size).decode()), block_size)[1]
    
    # Get padding to fit role value in one block
    start = len(test_input(""))
    for i in range(block_size):
        block_count = len(test_input('A'*i))
        
        if block_count > start:
            padding = 'A'*(i+len('user')-1)
            break

    # Replace role with admin
    blocks = split_blocks(test_input(padding), block_size)
    blocks[3] = admin_block
    return b''.join(blocks)


encrypted = attack()
print(encrypted)
print(read_full(encrypted))  # role: 'admin'
