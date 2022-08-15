
def has_duplicates(arr):
    seen = {}

    for x in arr:
        if x not in seen:
            seen[x] = 1
        else:
            return True
    
    return False

with open("set1/8.txt", "r") as f:
    for i, line in enumerate(f.readlines()):
        data = bytes.fromhex(line.replace("\n", ""))
        
        blocks = []
        for i in range(0, len(data), 16):  # Every 16 bytes
            blocks.append(data[i:i+16])
            
        if has_duplicates(blocks):
            print(i, line)
