import secrets
import string
from .decoder import get_random_byte, should_add_decoy

letters = list(string.ascii_lowercase)
# Create lookup table for O(1) index access instead of O(n) search
letter_to_index = {letter: i for i, letter in enumerate(letters)}


def create_random_cipher():
    cipher = letters.copy()

    for i in range(len(cipher) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        cipher[i], cipher[j] = cipher[j], cipher[i]

    return cipher


def create_decoy(key, position):
    random_byte = get_random_byte(key, position, "decoy")
    return letters[random_byte % 26]


def encode_message(message, cipher, key):
    encrypted_chars = []
    
    for position, character in enumerate(message):
        char_lower = character.lower()
        
        if char_lower in letter_to_index:
            index = letter_to_index[char_lower]
            encrypted = cipher[index]

            if character.isupper():
                encrypted = encrypted.upper()

            encrypted_chars.append(encrypted)
        else:
            encrypted_chars.append(character)

        if should_add_decoy(key, position):
            decoy = create_decoy(key, position)
            encrypted_chars.append(decoy)

    return ''.join(encrypted_chars)
