from Crypto.Cipher import AES
from base64 import b64decode

key = b"YELLOW SUBMARINE"
iv = b"\x00"*16

cipher = AES.new(key, AES.MODE_CBC, iv)

with open("set2/10.txt", "r") as f:
    data = b64decode(f.read().replace("\n", ""))
    print(cipher.decrypt(data).decode())
