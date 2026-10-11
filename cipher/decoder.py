import string
import hashlib
import ast

letters = list(string.ascii_lowercase)
# Create set for O(1) membership testing instead of O(n) list search
letters_set = set(letters)


def get_random_byte(key, position, extra=""):
    data = f"{key}:{position}:{extra}".encode("utf-8")
    digest = hashlib.sha256(data).digest()
    return digest[0]


def should_add_decoy(key, position):
    random_byte = get_random_byte(key, position, "position")
    return random_byte < 64


def create_decipher(cipher):
    decipher = {}
    for plain, encrypted in zip(letters, cipher):
        decipher[encrypted] = plain
        decipher[encrypted.upper()] = plain.upper()
    return decipher


def decode_message(coded_message, cipher, key):
    decipher = create_decipher(cipher)
    decoded_chars = []
    position = 0
    index = 0
    len_coded = len(coded_message)

    while index < len_coded:
        has_decoy = should_add_decoy(key, position)

        character = coded_message[index]

        if character in decipher:
            decoded_chars.append(decipher[character])
        else:
            decoded_chars.append(character)

        index += 1

        if has_decoy and index < len_coded:
            index += 1

        position += 1

    return ''.join(decoded_chars)


import ast
import string

def validate_cipher(cipher_input):
    letters_set = set(string.ascii_lowercase)
  
    if isinstance(cipher_input, str):
        try:
            cipher = ast.literal_eval(cipher_input)
        except (ValueError, SyntaxError):
            return False, "Invalid input format: could not parse input as a list"
        except NameError:
            return False, "Invalid input format: undefined name in input"
    else:
        cipher = cipher_input

    if not isinstance(cipher, list):
        return False, f"Cipher must be a list, got {type(cipher).__name__}"

    if len(cipher) != 26:
        return False, f"Cipher must contain exactly 26 letters, got {len(cipher)}"

    invalid_chars = []
    for i, letter in enumerate(cipher):
        if not isinstance(letter, str):
            invalid_chars.append(f"position {i + 1}: {letter!r} is not a string")
        elif len(letter) != 1:
            invalid_chars.append(f"position {i + 1}: {letter!r} is not a single character")
        elif letter.lower() not in letters_set:
            invalid_chars.append(f"position {i + 1}: {letter!r} is not a letter A–Z")

    if invalid_chars:
        return False, "Invalid character(s) found — " + "; ".join(invalid_chars)

    cipher = [letter.lower() for letter in cipher]

    seen = set()
    duplicates = []
    for letter in cipher:
        if letter in seen and letter not in duplicates:
            duplicates.append(letter)
        seen.add(letter)

    if duplicates:
        dup_str = ", ".join(sorted(duplicates))
        return False, f"Duplicate letter(s): {dup_str}"

    missing = sorted(letters_set - set(cipher))
    if missing:
        missing_str = ", ".join(missing)
        return False, f"Missing letter(s): {missing_str}"

    return True, cipher