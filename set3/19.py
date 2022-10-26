from Crypto.Cipher import AES
from base64 import b64decode
from string import ascii_letters
import os

BLOCK_SIZE = 16
KEY = os.urandom(16)

ALPHABET = list(b" {}_Ee3Aa@4RrIi1Oo0Tt7NnSs25$LlCcUuDdPpMmHhGg6BbFfYyWwKkVvXxZzJjQq89-,.!?'\"\n\r#%&()*+/\\:;<=>[]^`|~")  # Most common (in order)


data = [
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==", 
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=", 
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==", 
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=", 
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk", 
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", 
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=", 
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", 
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=", 
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl", 
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u", 
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==", 
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=", 
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==", 
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=", 
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", 
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==", 
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==", 
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==", 
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==", 
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==", 
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==", 
    "U2hlIHJvZGUgdG8gaGFycmllcnM/", 
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=", 
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=", 
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=", 
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=", 
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==", 
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==", 
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=", 
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==", 
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu", 
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=", 
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs", 
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=", 
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0", 
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7", 
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=", 
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=", 
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", 
]

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def ctr_keystream(key, nonce):
    cipher = AES.new(key, AES.MODE_ECB)
    
    counter = 0 
    nonce_bytes = nonce.to_bytes(BLOCK_SIZE // 2, 'little')
    while True:
        counter_bytes = counter.to_bytes(BLOCK_SIZE // 2, 'little')
        yield from cipher.encrypt(nonce_bytes + counter_bytes)
        counter += 1

def ctr_mode(s, key):
    return byte_xor(s, ctr_keystream(key, nonce=0))  # Fixed nonce to 0

def score_text(s):
    """Sum the index of the character in an ALPHABET ordered by frequency. Common characters get a high value, and uncommon letters get a low value"""
    return sum(len(ALPHABET) - ALPHABET.index(c) for c in s if c in ALPHABET)

all_encryped = [ctr_mode(b64decode(s), KEY) for s in data]

longest = 0
for e in all_encryped:
    if len(e) > longest:
        longest = len(e)
        
key = b""
for i in range(longest):  # Go over every letter in ciphertexts
    best_score = 0
    best_letter = None
    for letter in range(256):
        plaintext = [ciphertext[i] ^ letter for ciphertext in all_encryped if i < len(ciphertext)]
        score = score_text(plaintext) / len(plaintext)
        
        if score > best_score:
            best_score = score
            best_letter = letter
    
    key += bytes([best_letter])

    
for e in all_encryped:
    print(byte_xor(key, e))
