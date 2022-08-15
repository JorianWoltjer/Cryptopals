def unpad(s):
    padding = s[-1]
    for c in s[-padding:]:
        if c != padding:
            raise Exception("Invalid padding")

    return s[:-padding]


print(unpad(b"SOME16CHARACTERS\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"))
print(unpad(b"ICE ICE BABY\x04\x04\x04\x04"))
print(unpad(b"ICE ICE BABY\x05\x05\x05\x05"))
print(unpad(b"ICE ICE BABY\x01\x02\x03\x04"))
