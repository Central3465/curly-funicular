"""Slop coded Unit tests for the cipher module."""
import unittest
from cipher import (
    decode_message,
    create_decipher,
    validate_cipher,
    encode_message,
    create_random_cipher,
    convert_base,
    ascii_to_base,
    base_to_ascii,
)


class TestCreateDecipher(unittest.TestCase):
    """Tests for the create_decipher function."""

    def test_basic_cipher(self):
        """Test with a simple substitution cipher."""
        cipher = list("qwertyuiopasdfghjklzxcvbnm")
        decipher = create_decipher(cipher)

        # Check that all lowercase letters are mapped
        for i, letter in enumerate("abcdefghijklmnopqrstuvwxyz"):
            self.assertEqual(decipher[cipher[i]], letter)

    def test_uppercase_mapping(self):
        """Test that uppercase letters are properly mapped."""
        cipher = list("qwertyuiopasdfghjklzxcvbnm")
        decipher = create_decipher(cipher)

        # Check that uppercase letters are also mapped
        for i, letter in enumerate("abcdefghijklmnopqrstuvwxyz"):
            self.assertEqual(decipher[cipher[i].upper()], letter.upper())

    def test_identity_cipher(self):
        """Test with identity cipher (a->a, b->b, etc)."""
        cipher = list("abcdefghijklmnopqrstuvwxyz")
        decipher = create_decipher(cipher)

        for letter in "abcdefghijklmnopqrstuvwxyz":
            self.assertEqual(decipher[letter], letter)
            self.assertEqual(decipher[letter.upper()], letter.upper())


class TestValidateCipher(unittest.TestCase):
    """Tests for the validate_cipher function."""

    def test_valid_cipher_list(self):
        """Test with a valid cipher list."""
        cipher = list("qwertyuiopasdfghjklzxcvbnm")
        is_valid, result = validate_cipher(cipher)
        self.assertTrue(is_valid)
        self.assertEqual(result, cipher)

    def test_valid_cipher_string(self):
        """Test with a valid cipher as string representation."""
        cipher_str = "['q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m']"
        is_valid, result = validate_cipher(cipher_str)
        self.assertTrue(is_valid)
        self.assertEqual(len(result), 26)

    def test_invalid_length(self):
        """Test with cipher of incorrect length."""
        cipher = list("abcdefghijklmnopqrstuvwxy")  # 25 letters
        is_valid, message = validate_cipher(cipher)
        self.assertFalse(is_valid)
        self.assertIn("26", message)

    def test_invalid_non_list(self):
        """Test with non-list input."""
        is_valid, message = validate_cipher("not a list")
        self.assertFalse(is_valid)

    def test_invalid_duplicates(self):
        """Test with duplicate letters in cipher."""
        cipher = list("aabcdefghijklmnopqrstuvwxy")  # 'a' appears twice
        is_valid, message = validate_cipher(cipher)
        self.assertFalse(is_valid)
        self.assertIn("unique", message.lower())

    def test_invalid_non_letter(self):
        """Test with non-letter characters."""
        cipher = list("1bcdefghijklmnopqrstuvwxyz")  # '1' instead of 'a'
        is_valid, message = validate_cipher(cipher)
        self.assertFalse(is_valid)
        self.assertIn("letter", message.lower())

    def test_invalid_mixed_case(self):
        """Test that mixed case is normalized."""
        cipher = list("QWERTYUIOPASDFGHJKLZXCVBNM")
        is_valid, result = validate_cipher(cipher)
        self.assertTrue(is_valid)
        self.assertEqual(result, [c.lower() for c in cipher])


class TestEncodeDecodeMessage(unittest.TestCase):
    """Tests for encoding and decoding messages."""

    def setUp(self):
        """Set up test fixtures."""
        self.cipher = list("qwertyuiopasdfghjklzxcvbnm")
        self.key = "testkey"

    def test_encode_lowercase(self):
        """Test encoding lowercase letters."""
        message = "hello"
        encoded = encode_message(message, self.cipher, self.key)
        # First character should be encoded according to cipher
        # 'h' is at index 7, cipher[7] = 'i'
        self.assertEqual(encoded[0], 'i')

    def test_encode_uppercase(self):
        """Test that uppercase is preserved."""
        message = "HELLO"
        encoded = encode_message(message, self.cipher, self.key)
        # 'H' should map to uppercase of cipher[7] = 'I'
        self.assertEqual(encoded[0], 'I')

    def test_encode_preserves_spaces(self):
        """Test that spaces and special characters are preserved."""
        message = "hello world!"
        encoded = encode_message(message, self.cipher, self.key)
        # Spaces and punctuation should remain
        self.assertIn(' ', encoded)
        self.assertIn('!', encoded)

    def test_decode_roundtrip(self):
        """Test that decoding an encoded message returns original."""
        message = "The quick brown fox jumps over the lazy dog"
        encoded = encode_message(message, self.cipher, self.key)
        decoded = decode_message(encoded, self.cipher, self.key)
        self.assertEqual(decoded, message)

    def test_empty_message(self):
        """Test encoding/decoding empty message."""
        message = ""
        encoded = encode_message(message, self.cipher, self.key)
        decoded = decode_message(encoded, self.cipher, self.key)
        self.assertEqual(encoded, "")
        self.assertEqual(decoded, "")

    def test_special_characters_only(self):
        """Test with only special characters."""
        message = "!@#$%^&*()"
        encoded = encode_message(message, self.cipher, self.key)
        decoded = decode_message(encoded, self.cipher, self.key)
        # Decoded should match original (encoded may have decoys)
        self.assertEqual(decoded, message)

    def test_different_keys(self):
        """Test that different keys produce different encodings."""
        message = "test"
        encoded1 = encode_message(message, self.cipher, "key1")
        encoded2 = encode_message(message, self.cipher, "key2")
        # Due to decoys, different keys should produce different results
        self.assertNotEqual(encoded1, encoded2)


class TestCreateRandomCipher(unittest.TestCase):
    """Tests for the create_random_cipher function."""

    def test_returns_list(self):
        """Test that function returns a list."""
        cipher = create_random_cipher()
        self.assertIsInstance(cipher, list)

    def test_correct_length(self):
        """Test that cipher has 26 elements."""
        cipher = create_random_cipher()
        self.assertEqual(len(cipher), 26)

    def test_all_letters_present(self):
        """Test that all 26 letters are present."""
        cipher = create_random_cipher()
        cipher_lower = [c.lower() for c in cipher]
        expected = set("abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(set(cipher_lower), expected)

    def test_unique_letters(self):
        """Test that all letters are unique."""
        cipher = create_random_cipher()
        cipher_lower = [c.lower() for c in cipher]
        self.assertEqual(len(set(cipher_lower)), 26)

    def test_different_each_time(self):
        """Test that multiple calls produce different ciphers."""
        cipher1 = create_random_cipher()
        cipher2 = create_random_cipher()
        # Very unlikely to be the same
        self.assertNotEqual(cipher1, cipher2)


class TestConvertBase(unittest.TestCase):
    """Tests for the convert_base function."""

    def test_binary_to_decimal(self):
        """Test binary to decimal conversion."""
        result = convert_base("1010", 2, 10)
        self.assertEqual(result, "10")

    def test_decimal_to_binary(self):
        """Test decimal to binary conversion."""
        result = convert_base("10", 10, 2)
        self.assertEqual(result, "1010")

    def test_decimal_to_hexadecimal(self):
        """Test decimal to hexadecimal conversion."""
        result = convert_base("255", 10, 16)
        self.assertEqual(result, "FF")

    def test_hexadecimal_to_decimal(self):
        """Test hexadecimal to decimal conversion."""
        result = convert_base("FF", 16, 10)
        self.assertEqual(result, "255")

    def test_zero_conversion(self):
        """Test conversion of zero."""
        self.assertEqual(convert_base("0", 10, 2), "0")
        self.assertEqual(convert_base("0", 2, 16), "0")

    def test_same_base(self):
        """Test conversion to same base."""
        result = convert_base("123", 10, 10)
        self.assertEqual(result, "123")

    def test_base36(self):
        """Test base 36 conversion."""
        result = convert_base("10", 10, 36)
        self.assertEqual(result, "A")


class TestAsciiToBase(unittest.TestCase):
    """Tests for the ascii_to_base function."""

    def test_simple_text_binary(self):
        """Test converting simple text to binary."""
        result = ascii_to_base("A", 2)
        self.assertEqual(result, "1000001")  # ASCII 65 = 1000001

    def test_multiple_characters(self):
        """Test converting multiple characters."""
        result = ascii_to_base("AB", 2)
        # A = 65 = 1000001, B = 66 = 1000010
        self.assertEqual(result, "1000001 1000010")

    def test_hexadecimal(self):
        """Test converting to hexadecimal."""
        result = ascii_to_base("A", 16)
        self.assertEqual(result, "41")  # ASCII 65 = 0x41

    def test_space_separated(self):
        """Test that output is space-separated."""
        result = ascii_to_base("ABC", 10)
        parts = result.split()
        self.assertEqual(len(parts), 3)


class TestBaseToAscii(unittest.TestCase):
    """Tests for the base_to_ascii function."""

    def test_binary_to_ascii(self):
        """Test converting binary to ASCII."""
        result = base_to_ascii("1000001", 2)
        self.assertEqual(result, "A")

    def test_multiple_numbers(self):
        """Test converting multiple numbers."""
        result = base_to_ascii("1000001 1000010", 2)
        self.assertEqual(result, "AB")

    def test_hexadecimal_to_ascii(self):
        """Test converting hexadecimal to ASCII."""
        result = base_to_ascii("41 42 43", 16)
        self.assertEqual(result, "ABC")

    def test_invalid_ascii_value(self):
        """Test that invalid ASCII values raise error."""
        with self.assertRaises(ValueError):
            base_to_ascii("200", 10)  # 200 > 127

    def test_roundtrip(self):
        """Test that base_to_ascii(ascii_to_base(x)) == x."""
        original = "Hello"
        converted = ascii_to_base(original, 2)
        back = base_to_ascii(converted, 2)
        self.assertEqual(back, original)


if __name__ == "__main__":
    unittest.main()
