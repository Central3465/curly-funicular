import secrets
import string
from .decoder import get_random_byte, should_add_decoy

letters = list(string.ascii_lowercase)


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
    encrypted_message = ""

    for position, character in enumerate(message):

        if character.lower() in letters:
            index = letters.index(character.lower())
            encrypted = cipher[index]

            if character.isupper():
                encrypted = encrypted.upper()

            encrypted_message += encrypted

        else:
            encrypted_message += character

        if should_add_decoy(key, position):
            decoy = create_decoy(key, position)
            encrypted_message += decoy

    return encrypted_message
