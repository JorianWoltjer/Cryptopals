from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pwn import xor

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
    s = escape(s)  # Filter
    data = b"comment1=cooking%20MCs;userdata=" + s + b";comment2=%20like%20a%20pound%20of%20bacon"
    
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    return cipher.encrypt(pad(data, 16))

def check(encrypted):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    s = cipher.decrypt(encrypted)
    print(s)
    
    return b";admin=true;" in s

def test_decrypt(encrypted):  # May not be used for attack
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    
    return cipher.decrypt(encrypted)

# Attack

def xor(s1, s2):
    """byte XOR *without* repeating key, after key runs out plaintext continues"""
    assert len(s1) >= len(s2), "First argument should be longest"
    max_length = len(s1)
    min_length = len(s2)
    return bytes(s1[i] ^ s2[i] if i < min_length else s1[i] for i in range(max_length))

def flip_to_goal(plaintext, ciphertext, goal, input_block):
    """
    :param plaintext: The original plaintext
    :param ciphertext: The ciphertext after encrypting original plaintext
    :param goal: The plaintext that the resulting ciphertext should decrypt to
    :param input_block: The number of the block that the input is in
    :return: The altered ciphertext that decrypts to goal
    """
    assert (len(plaintext)-1)//16 == (len(goal)-1)//16, "Plaintext and goal must have same number of blocks"
    
    difference = xor(plaintext, goal)  # XOR is the same as flipping bits
    assert difference[:16] == b"\x00"*16, "First block cannot be changed"
    difference = b"\x00"*16*input_block + difference  # Padding to get difference in right place
    
    return xor(ciphertext, difference[16:])  # Flip the bits on ciphertext (one block before)


plaintext = b"A"*16 + b"B"*16  # First send BBBB...
ciphertext = user_input(plaintext)
goal = b"A"*16 + b";admin=true;"  # Then change to inject admin=true without going through escape() function

new_ciphertext = flip_to_goal(plaintext, ciphertext, goal, input_block=2)

print(check(new_ciphertext))  # "Submit"
