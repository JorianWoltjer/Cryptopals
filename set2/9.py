s = b"YELLOW SUBMARINE"

def pad(s, n):
    pad_length = n - len(s) % n
    if pad_length == n:  # Don't pad unnecessarily 
        pad_length = 0
    
    return s + bytes([pad_length])*pad_length

print(pad(s, 20))
