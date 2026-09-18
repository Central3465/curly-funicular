"""Unit tests for user API endpoints."""
import unittest
import json
from app import app, users_collection
import bcrypt
from datetime import datetime
from bson.objectid import ObjectId


class UserAPITestCase(unittest.TestCase):
    """Base test case for user API tests with authentication setup."""

    def setUp(self):
        """Set up test client and authenticated session."""
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        if users_collection is None:
            self.skipTest("Database connection not available")

        # Create and login test user
        self.email = 'usertest@example.com'
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
        self.user_id = str(self.user.inserted_id)

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


class TestUserDataEndpoint(UserAPITestCase):
    """Tests for user-data endpoint."""

    def test_get_user_data_success(self):
        """Test retrieving user data."""
        response = self.make_authenticated_request('GET', '/api/user-data')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)

        self.assertEqual(data['email'], self.email)
        self.assertIn('created_at', data)
        self.assertIn('banned', data)

    def test_get_user_data_contains_email(self):
        """Test that user data contains email."""
        response = self.make_authenticated_request('GET', '/api/user-data')
        data = json.loads(response.data)
        self.assertEqual(data['email'], self.email)

    def test_get_user_data_contains_banned_status(self):
        """Test that user data contains banned status."""
        response = self.make_authenticated_request('GET', '/api/user-data')
        data = json.loads(response.data)
        self.assertFalse(data['banned'])

    def test_get_user_data_contains_created_at(self):
        """Test that user data contains created_at timestamp."""
        response = self.make_authenticated_request('GET', '/api/user-data')
        data = json.loads(response.data)
        self.assertIsInstance(data['created_at'], str)
        self.assertNotEqual(data['created_at'], 'Unknown')

    def test_get_user_data_unauthorized(self):
        """Test that unauthenticated users cannot get user data."""
        self.client.post('/api/logout')
        response = self.client.get('/api/user-data')
        self.assertEqual(response.status_code, 401)

    def test_get_banned_user_data(self):
        """Test retrieving data of a banned user."""
        # Ban the user
        users_collection.update_one(
            {'_id': ObjectId(self.user_id)},
            {'$set': {'banned': True}}
        )

        # Get user data
        response = self.make_authenticated_request('GET', '/api/user-data')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['banned'])

    def test_get_nonexistent_user_data(self):
        """Test retrieving data for nonexistent user ID in session."""
        # Manually set invalid user_id in session
        with self.client.session_transaction() as sess:
            sess['user_id'] = str(ObjectId())

        response = self.client.get('/api/user-data')
        self.assertEqual(response.status_code, 404)


class TestAuthenticationProtection(UserAPITestCase):
    """Tests for protected endpoint authentication."""

    def test_validate_cipher_requires_auth(self):
        """Test that validate-cipher requires authentication."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/validate-cipher',
            data=json.dumps({'cipher': list('abcdefghijklmnopqrstuvwxyz')}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)

    def test_encode_requires_auth(self):
        """Test that encode requires authentication."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/encode',
            data=json.dumps({
                'cipher': list('abcdefghijklmnopqrstuvwxyz'),
                'message': 'test',
                'key': 'key'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)

    def test_decode_requires_auth(self):
        """Test that decode requires authentication."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/decode',
            data=json.dumps({
                'cipher': list('abcdefghijklmnopqrstuvwxyz'),
                'message': 'test',
                'key': 'key'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)

    def test_generate_cipher_requires_auth(self):
        """Test that generate-cipher requires authentication."""
        self.client.post('/api/logout')
        response = self.client.post('/api/generate-cipher')
        self.assertEqual(response.status_code, 401)

    def test_convert_base_requires_auth(self):
        """Test that convert-base requires authentication."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/convert-base',
            data=json.dumps({'number': '10', 'from_base': 10, 'to_base': 2}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)

    def test_ascii_to_base_requires_auth(self):
        """Test that ascii-to-base requires authentication."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/ascii-to-base',
            data=json.dumps({'text': 'A', 'base': 10}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)

    def test_base_to_ascii_requires_auth(self):
        """Test that base-to-ascii requires authentication."""
        self.client.post('/api/logout')
        response = self.client.post(
            '/api/base-to-ascii',
            data=json.dumps({'numbers': '65', 'base': 10}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)


class TestSessionHandling(UserAPITestCase):
    """Tests for session handling."""

    def test_session_persists_across_requests(self):
        """Test that session persists across multiple requests."""
        # Make first request
        response1 = self.make_authenticated_request('GET', '/api/user-data')
        self.assertEqual(response1.status_code, 200)

        # Make second request - should still be authenticated
        response2 = self.make_authenticated_request('GET', '/api/user-data')
        self.assertEqual(response2.status_code, 200)

    def test_logout_clears_authentication(self):
        """Test that logout actually clears authentication."""
        # Verify authenticated
        response1 = self.make_authenticated_request('GET', '/api/user-data')
        self.assertEqual(response1.status_code, 200)

        # Logout
        self.client.post('/api/logout')

        # Verify not authenticated
        response2 = self.client.get('/api/user-data')
        self.assertEqual(response2.status_code, 401)

    def test_different_users_have_different_sessions(self):
        """Test that different users have separate sessions."""
        # Create second user
        email2 = 'usertest2@example.com'
        password2 = 'testpass456'
        hashed_pw2 = bcrypt.hashpw(
            password2.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        users_collection.delete_one({'email': email2})
        users_collection.insert_one({
            'email': email2,
            'password': hashed_pw2,
            'banned': False
        })

        try:
            # Get first user's data
            response1 = self.make_authenticated_request('GET', '/api/user-data')
            data1 = json.loads(response1.data)
            self.assertEqual(data1['email'], self.email)

            # Logout and login as second user
            self.client.post('/api/logout')
            self.client.post(
                '/api/login',
                data=json.dumps({'email': email2, 'password': password2}),
                content_type='application/json'
            )

            # Get second user's data
            response2 = self.client.get('/api/user-data')
            data2 = json.loads(response2.data)
            self.assertEqual(data2['email'], email2)
            self.assertNotEqual(data1['email'], data2['email'])
        finally:
            users_collection.delete_one({'email': email2})


if __name__ == '__main__':
    unittest.main()
