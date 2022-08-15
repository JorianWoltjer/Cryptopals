import spacy
from spacy.language import Language
from spacy_langdetect import LanguageDetector

s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
alphabet = "abcdefghijklmnopqrstuvwxyz"

def get_lang_detector(nlp, name):
    return LanguageDetector()

nlp = spacy.load("en_core_web_sm")
Language.factory("language_detector", func=get_lang_detector)
nlp.add_pipe('language_detector', last=True)

def get_score(s):
    doc = nlp(s)
    return doc._.language

def xor(s1, s2):
    return bytes([c1 ^ c2 for c1, c2 in zip(s1, s2)])

def normalize(s):
    result = ''
    for c in s:
        if 20 < c < 128:
            result += chr(c).lower()
        else:
            result += ' '
        
    return result


for key in alphabet:
    d = xor(bytes.fromhex(s), bytes(key*len(s), 'utf8'))
    d = normalize(d)
    result = get_score(d)
    if result['language'] == 'en' and result['score'] > 0.99:
        print(key, result, d)
