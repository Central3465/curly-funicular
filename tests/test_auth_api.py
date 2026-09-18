"""Unit tests for authentication API endpoints."""
import unittest
import json
from app import app, users_collection, login_attempts, access_requests, limiter
import bcrypt
import pymongo

class TestAuthAPI(unittest.TestCase):
    """Tests for authentication endpoints."""

    def setUp(self):
        """Set up test client and database."""
        self.app = app
        self.app.config['TESTING'] = True
        limiter.enabled = False
        self.client = self.app.test_client()

        # Clear login attempts and access requests
        login_attempts.clear()
        access_requests.clear()

        # Skip if database is not available
        if users_collection is None:
            self.skipTest("Database connection not available")

    def tearDown(self):
        """Clean up after tests."""
        login_attempts.clear()
        access_requests.clear()

    def test_register_disabled(self):
        """Test that registration returns 403."""
        response = self.client.post(
            '/api/register',
            data=json.dumps({'email': 'test@example.com', 'password': 'password'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.data)
        self.assertIn('disabled', data['error'].lower())

    def test_login_missing_credentials(self):
        """Test login with missing email or password."""
        # Missing email
        response = self.client.post(
            '/api/login',
            data=json.dumps({'password': 'password'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)

        # Missing password
        response = self.client.post(
            '/api/login',
            data=json.dumps({'email': 'test@example.com'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)

    def test_login_invalid_email_password(self):
        """Test login with invalid credentials."""
        response = self.client.post(
            '/api/login',
            data=json.dumps({'email': 'nonexistent@example.com', 'password': 'wrong'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertIn('Invalid', data['error'])

    def test_login_rate_limiting(self):
        """Test that repeated failed attempts block IP."""
        # Create test user
        email = 'ratelimit@example.com'
        password = 'testpass'
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        users_collection.delete_one({'email': email})
        users_collection.insert_one({
            'email': email,
            'password': hashed_pw,
            'banned': False
        })

        try:
            # Make 4 failed attempts (should return 401)
            for i in range(4):
                response = self.client.post(
                    '/api/login',
                    data=json.dumps({'email': email, 'password': 'wrongpassword'}),
                    content_type='application/json'
                )
                self.assertEqual(response.status_code, 401)

            # 5th attempt should be blocked (hits max limit)
            response = self.client.post(
                '/api/login',
                data=json.dumps({'email': email, 'password': 'wrongpassword'}),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 429)
            data = json.loads(response.data)
            self.assertIn('blocked', data['error'].lower())
        finally:
            users_collection.delete_one({'email': email})

    def test_login_banned_account(self):
        """Test that banned users cannot login."""
        email = 'banned@example.com'
        password = 'testpass'
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        users_collection.delete_one({'email': email})
        users_collection.insert_one({
            'email': email,
            'password': hashed_pw,
            'banned': True
        })

        try:
            response = self.client.post(
                '/api/login',
                data=json.dumps({'email': email, 'password': password}),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 403)
            data = json.loads(response.data)
            self.assertIn('banned', data['error'].lower())
        finally:
            users_collection.delete_one({'email': email})

    def test_logout_clears_session(self):
        """Test that logout clears session."""
        response = self.client.post('/api/logout')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])


class TestLoginFlow(unittest.TestCase):
    """Tests for complete login flow."""

    def setUp(self):
        """Set up test client and test user."""
        self.app = app
        self.app.config['TESTING'] = True
        limiter.enabled = False
        self.client = self.app.test_client()

        if users_collection is None:
            self.skipTest("Database connection not available")

        # Create test user
        self.email = 'logintest@example.com'
        self.password = 'testpass123'
        hashed_pw = bcrypt.hashpw(
            self.password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        users_collection.delete_one({'email': self.email})
        self.user = users_collection.insert_one({
            'email': self.email,
            'password': hashed_pw,
            'banned': False
        })

        login_attempts.clear()

    def tearDown(self):
        """Clean up test user."""
        users_collection.delete_one({'email': self.email})
        login_attempts.clear()

    def test_successful_login(self):
        """Test successful login."""
        response = self.client.post(
            '/api/login',
            data=json.dumps({'email': self.email, 'password': self.password}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])

    def test_login_email_case_insensitive(self):
        """Test that email comparison is case-insensitive."""
        response = self.client.post(
            '/api/login',
            data=json.dumps({
                'email': self.email.upper(),
                'password': self.password
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
