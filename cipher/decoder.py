import string
import hashlib

letters = list(string.ascii_lowercase)


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
    decoded_message = ""
    position = 0
    index = 0

    while index < len(coded_message):
        has_decoy = should_add_decoy(key, position)

        if index >= len(coded_message):
            break

        character = coded_message[index]

        if character in decipher:
            decoded_message += decipher[character]
        else:
            decoded_message += character

        index += 1

        if has_decoy:
            if index < len(coded_message):
                index += 1

        position += 1

    return decoded_message


def validate_cipher(cipher_input):
    try:
        cipher = eval(cipher_input) if isinstance(cipher_input, str) else cipher_input

        if not isinstance(cipher, list):
            return False, "Cipher must be a list"

        if len(cipher) != 26:
            return False, "Cipher must contain exactly 26 letters"

        if any(
            not isinstance(letter, str)
            or len(letter) != 1
            or letter.lower() not in letters
            for letter in cipher
        ):
            return False, "All items must be single letters"

        cipher = [letter.lower() for letter in cipher]

        if len(set(cipher)) != 26:
            return False, "All letters must be unique"

        return True, cipher
    except (ValueError, SyntaxError, NameError):
        return False, "Invalid input format"
