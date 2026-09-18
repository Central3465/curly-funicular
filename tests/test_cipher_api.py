"""Unit tests for cipher API endpoints."""
import unittest
import json
from app import app, users_collection, limiter
from cipher import create_random_cipher
import bcrypt
from datetime import datetime
import pymongo

class CipherAPITestCase(unittest.TestCase):
    """Base test case for cipher API tests with authentication setup."""

    def setUp(self):
        """Set up test client and authenticated session."""
        self.app = app
        self.app.config['TESTING'] = True
        limiter.enabled = False
        self.client = self.app.test_client()

        if users_collection is None:
            self.skipTest("Database connection not available")

        # Create and login test user
        self.email = 'ciphertest@example.com'
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


class TestValidateCipherEndpoint(CipherAPITestCase):
    """Tests for validate-cipher endpoint."""

    def test_validate_cipher_valid(self):
        """Test validating a valid cipher."""
        cipher = create_random_cipher()
        response = self.make_authenticated_request(
            'POST',
            '/api/validate-cipher',
            {'cipher': cipher}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['valid'])

    def test_validate_cipher_invalid_length(self):
        """Test validating cipher with wrong length."""
        cipher = list("abcdefghijklmnopqrstuvwxy")  # Only 25
        response = self.make_authenticated_request(
            'POST',
            '/api/validate-cipher',
            {'cipher': cipher}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertFalse(data['valid'])

    def test_validate_cipher_unauthorized(self):
        """Test that unauthenticated user cannot validate cipher."""
        self.client.post('/api/logout')
        cipher = create_random_cipher()
        response = self.client.post(
            '/api/validate-cipher',
            data=json.dumps({'cipher': cipher}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)


class TestGenerateCipherEndpoint(CipherAPITestCase):
    """Tests for generate-cipher endpoint."""

    def test_generate_cipher_success(self):
        """Test generating a random cipher."""
        response = self.make_authenticated_request('POST', '/api/generate-cipher')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('cipher', data)
        self.assertEqual(len(data['cipher']), 26)

    def test_generate_cipher_returns_list(self):
        """Test that generated cipher is a list."""
        response = self.make_authenticated_request('POST', '/api/generate-cipher')
        data = json.loads(response.data)
        self.assertIsInstance(data['cipher'], list)

    def test_generate_cipher_unauthorized(self):
        """Test that unauthenticated user cannot generate cipher."""
        self.client.post('/api/logout')
        response = self.client.post('/api/generate-cipher')
        self.assertEqual(response.status_code, 401)


class TestEncodeCipherEndpoint(CipherAPITestCase):
    """Tests for encode endpoint."""

    def setUp(self):
        """Set up test with generated cipher."""
        super().setUp()
        self.cipher = create_random_cipher()
        self.key = "testkey"
        self.message = "hello world"

    def test_encode_success(self):
        """Test successful encoding."""
        response = self.make_authenticated_request(
            'POST',
            '/api/encode',
            {
                'cipher': self.cipher,
                'message': self.message,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('encrypted', data)

    def test_encode_missing_key(self):
        """Test encoding without key."""
        response = self.make_authenticated_request(
            'POST',
            '/api/encode',
            {
                'cipher': self.cipher,
                'message': self.message
            }
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('Key', data['error'])

    def test_encode_invalid_cipher(self):
        """Test encoding with invalid cipher."""
        response = self.make_authenticated_request(
            'POST',
            '/api/encode',
            {
                'cipher': list("abcdefghijklmnopqrstuvwxy"),
                'message': self.message,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 400)

    def test_encode_empty_message(self):
        """Test encoding empty message."""
        response = self.make_authenticated_request(
            'POST',
            '/api/encode',
            {
                'cipher': self.cipher,
                'message': '',
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['encrypted'], '')


class TestDecodeCipherEndpoint(CipherAPITestCase):
    """Tests for decode endpoint."""

    def setUp(self):
        """Set up test with cipher and encoded message."""
        super().setUp()
        self.cipher = create_random_cipher()
        self.key = "testkey"
        self.message = "hello world"

        # Generate encoded message for testing
        response = self.make_authenticated_request(
            'POST',
            '/api/encode',
            {
                'cipher': self.cipher,
                'message': self.message,
                'key': self.key
            }
        )
        self.encrypted_message = json.loads(response.data)['encrypted']

    def test_decode_success(self):
        """Test successful decoding."""
        response = self.make_authenticated_request(
            'POST',
            '/api/decode',
            {
                'cipher': self.cipher,
                'message': self.encrypted_message,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('decoded', data)
        self.assertEqual(data['decoded'], self.message)

    def test_decode_missing_key(self):
        """Test decoding without key."""
        response = self.make_authenticated_request(
            'POST',
            '/api/decode',
            {
                'cipher': self.cipher,
                'message': self.encrypted_message
            }
        )
        self.assertEqual(response.status_code, 400)

    def test_decode_invalid_cipher(self):
        """Test decoding with invalid cipher."""
        response = self.make_authenticated_request(
            'POST',
            '/api/decode',
            {
                'cipher': list("abcdefghijklmnopqrstuvwxy"),
                'message': self.encrypted_message,
                'key': self.key
            }
        )
        self.assertEqual(response.status_code, 400)

    def test_decode_wrong_key(self):
        """Test decoding with wrong key produces wrong result."""
        response = self.make_authenticated_request(
            'POST',
            '/api/decode',
            {
                'cipher': self.cipher,
                'message': self.encrypted_message,
                'key': 'wrongkey'
            }
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        # Decoding with wrong key should not produce original message
        self.assertNotEqual(data['decoded'], self.message)

    def test_decode_roundtrip(self):
        """Test that encode->decode produces original message."""
        response = self.make_authenticated_request(
            'POST',
            '/api/decode',
            {
                'cipher': self.cipher,
                'message': self.encrypted_message,
                'key': self.key
            }
        )
        data = json.loads(response.data)
        self.assertEqual(data['decoded'], self.message)


if __name__ == '__main__':
    unittest.main()
