s1 = "1c0111001f010100061a024b53535009181c"
s2 = "686974207468652062756c6c277320657965"

def xor(s1, s2):
    return bytes([c1 ^ c2 for c1, c2 in zip(s1, s2)])

r = xor(bytes.fromhex(s1), bytes.fromhex(s2))

print(r.hex())
