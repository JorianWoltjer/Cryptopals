from Crypto.Cipher import AES
from base64 import b64decode

key = b"YELLOW SUBMARINE"

cipher = AES.new(key, AES.MODE_ECB)

with open("set1/7.txt", "r") as f:
    data = b64decode(f.read().replace("\n", ""))
    print(cipher.decrypt(data).decode())
