"""Unit tests for conversion API endpoints."""
import unittest
import json
from app import app, users_collection
import bcrypt
from datetime import datetime


class ConversionAPITestCase(unittest.TestCase):
    """Base test case for conversion API tests with authentication setup."""

    def setUp(self):
        """Set up test client and authenticated session."""
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        if users_collection is None:
            self.skipTest("Database connection not available")

        # Create and login test user
        self.email = 'convtest@example.com'
        self.password = 'testpass123'
        hashed_pw = bcrypt.hashpw(
            self.password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        users_collection.delete_one({'email': self.email})
        self.user = users_collection.insert_one({
            'email': self.email,
            'password': hashed_pw,
            'banned': False,
            'created_at': datetime.now()
        })

        # Login
        self.login()

    def tearDown(self):
        """Clean up test user."""
        users_collection.delete_one({'email': self.email})

    def login(self):
        """Login test user."""
        response = self.client.post(
            '/api/login',
            data=json.dumps({'email': self.email, 'password': self.password}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)

    def make_authenticated_request(self, method, path, data=None):
        """Make authenticated API request."""
        if method == 'POST':
            return self.client.post(
                path,
                data=json.dumps(data) if data else None,
                content_type='application/json'
            )
        elif method == 'GET':
            return self.client.get(path)


class TestConvertBaseEndpoint(ConversionAPITestCase):
    """Tests for convert-base endpoint."""

    def test_convert_binary_to_decimal(self):
        """Test converting binary to decimal."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '1010', 'from_base': 2, 'to_base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['result'], '10')

    def test_convert_decimal_to_binary(self):
        """Test converting decimal to binary."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '10', 'from_base': 10, 'to_base': 2}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], '1010')

    def test_convert_decimal_to_hex(self):
        """Test converting decimal to hexadecimal."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '255', 'from_base': 10, 'to_base': 16}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'].upper(), 'FF')

    def test_convert_hex_to_decimal(self):
        """Test converting hexadecimal to decimal."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': 'FF', 'from_base': 16, 'to_base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], '255')

    def test_convert_zero(self):
        """Test converting zero."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '0', 'from_base': 10, 'to_base': 2}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], '0')

    def test_convert_same_base(self):
        """Test conversion to same base."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '123', 'from_base': 10, 'to_base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], '123')

    def test_convert_base36(self):
        """Test base 36 conversion."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '10', 'from_base': 10, 'to_base': 36}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'].upper(), 'A')

    def test_convert_empty_number(self):
        """Test with empty number."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '', 'from_base': 10, 'to_base': 2}
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('empty', data['error'].lower())

    def test_convert_invalid_base_low(self):
        """Test with base less than 2."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '10', 'from_base': 1, 'to_base': 10}
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('Base', data['error'])

    def test_convert_invalid_base_high(self):
        """Test with base greater than 36."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '10', 'from_base': 10, 'to_base': 37}
        )
        self.assertEqual(response.status_code, 400)

    def test_convert_invalid_number_for_base(self):
        """Test with invalid number for given base."""
        response = self.make_authenticated_request(
            'POST',
            '/api/convert-base',
            {'number': '2', 'from_base': 2, 'to_base': 10}
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('Invalid', data['error'])

    def test_convert_unauthorized(self):
        """Test that unauthenticated user cannot convert."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/convert-base',
            data=json.dumps({'number': '10', 'from_base': 10, 'to_base': 2}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)


class TestAsciiToBaseEndpoint(ConversionAPITestCase):
    """Tests for ascii-to-base endpoint."""

    def test_ascii_to_binary(self):
        """Test converting ASCII to binary."""
        response = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': 'A', 'base': 2}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['result'], '1000001')

    def test_ascii_to_hex(self):
        """Test converting ASCII to hexadecimal."""
        response = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': 'A', 'base': 16}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'].upper(), '41')

    def test_ascii_to_decimal(self):
        """Test converting ASCII to decimal."""
        response = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': 'A', 'base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], '65')

    def test_multiple_characters(self):
        """Test converting multiple characters."""
        response = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': 'ABC', 'base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        # Should be space-separated
        parts = data['result'].split()
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], '65')  # A
        self.assertEqual(parts[1], '66')  # B
        self.assertEqual(parts[2], '67')  # C

    def test_ascii_with_spaces(self):
        """Test converting text with spaces."""
        response = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': 'A B', 'base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        parts = data['result'].split()
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[1], '32')  # Space

    def test_empty_text(self):
        """Test with empty text."""
        response = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': '', 'base': 10}
        )
        self.assertEqual(response.status_code, 400)

    def test_invalid_base(self):
        """Test with invalid base."""
        response = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': 'A', 'base': 1}
        )
        self.assertEqual(response.status_code, 400)

    def test_unauthorized(self):
        """Test that unauthenticated user cannot convert."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/ascii-to-base',
            data=json.dumps({'text': 'A', 'base': 10}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)


class TestBaseToAsciiEndpoint(ConversionAPITestCase):
    """Tests for base-to-ascii endpoint."""

    def test_binary_to_ascii(self):
        """Test converting binary to ASCII."""
        response = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': '1000001', 'base': 2}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['result'], 'A')

    def test_hex_to_ascii(self):
        """Test converting hexadecimal to ASCII."""
        response = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': '41', 'base': 16}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], 'A')

    def test_decimal_to_ascii(self):
        """Test converting decimal to ASCII."""
        response = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': '65', 'base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], 'A')

    def test_multiple_numbers(self):
        """Test converting multiple numbers."""
        response = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': '65 66 67', 'base': 10}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['result'], 'ABC')

    def test_roundtrip_conversion(self):
        """Test that base-to-ascii(ascii-to-base(x)) == x."""
        original_text = 'Hello'

        # ASCII to base
        response1 = self.make_authenticated_request(
            'POST',
            '/api/ascii-to-base',
            {'text': original_text, 'base': 2}
        )
        converted = json.loads(response1.data)['result']

        # Base to ASCII
        response2 = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': converted, 'base': 2}
        )
        back = json.loads(response2.data)['result']

        self.assertEqual(back, original_text)

    def test_empty_numbers(self):
        """Test with empty numbers."""
        response = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': '', 'base': 10}
        )
        self.assertEqual(response.status_code, 400)

    def test_invalid_ascii_value(self):
        """Test with value outside ASCII range."""
        response = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': '200', 'base': 10}
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('Invalid', data['error'])

    def test_invalid_base(self):
        """Test with invalid base."""
        response = self.make_authenticated_request(
            'POST',
            '/api/base-to-ascii',
            {'numbers': '41', 'base': 37}
        )
        self.assertEqual(response.status_code, 400)

    def test_unauthorized(self):
        """Test that unauthenticated user cannot convert."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/base-to-ascii',
            data=json.dumps({'numbers': '65', 'base': 10}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
