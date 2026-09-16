def convert_base(number, from_base, to_base):
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    decimal = int(number, from_base)

    if to_base == 10:
        return str(decimal)

    if decimal == 0:
        return "0"

    result = ""

    while decimal > 0:
        remainder = decimal % to_base
        result = digits[remainder] + result
        decimal //= to_base

    return result


def ascii_to_base(text, base):
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = []

    for character in text:
        value = ord(character)

        if value == 0:
            result.append("0")
            continue

        converted = ""

        while value > 0:
            remainder = value % base
            converted = digits[remainder] + converted
            value //= base

        result.append(converted)

    return " ".join(result)


def base_to_ascii(numbers, base):
    characters = []

    for number in numbers.split():
        value = int(number, base)

        if value < 0 or value > 127:
            raise ValueError(
                f"{number} does not represent a standard ASCII character."
            )

        characters.append(chr(value))

    return "".join(characters)
