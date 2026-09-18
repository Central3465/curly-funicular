"""Unit tests for admin API endpoints."""
import unittest
import json
from app import app, users_collection, limiter
import bcrypt
from datetime import datetime
from bson.objectid import ObjectId
import pymongo

class AdminAPITestCase(unittest.TestCase):
    """Base test case for admin API tests with authentication setup."""

    def setUp(self):
        """Set up test client and authenticated session."""
        self.app = app
        self.app.config['TESTING'] = True
        limiter.enabled = False
        self.client = self.app.test_client()

        if users_collection is None:
            self.skipTest("Database connection not available")

        # Create and login admin user
        self.admin_email = 'hanlinbai667@gmail.com'
        self.admin_password = 'adminpass123'
        hashed_pw = bcrypt.hashpw(
            self.admin_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        users_collection.delete_one({'email': self.admin_email})
        self.admin_user = users_collection.insert_one({
            'email': self.admin_email,
            'password': hashed_pw,
            'banned': False,
            'isAdmin': True,
            'created_at': datetime.now()
        })

        # Login as admin
        self.login_admin()

    def login_admin(self):
        """Login admin user."""
        response = self.client.post(
            '/api/login',
            data=json.dumps({'email': self.admin_email, 'password': self.admin_password}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)

    def create_test_user(self, email, password='testpass123', banned=False):
        """Create a test user for testing."""
        hashed_pw = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        users_collection.delete_one({'email': email})
        user = users_collection.insert_one({
            'email': email,
            'password': hashed_pw,
            'banned': banned,
            'created_at': datetime.now()
        })
        return str(user.inserted_id)

    def tearDown(self):
        """Clean up test users."""
        users_collection.delete_one({'email': self.admin_email})

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


class TestAdminAccessControl(AdminAPITestCase):
    """Tests for admin access control."""

    def test_non_admin_cannot_access_admin_endpoints(self):
        """Test that non-admin users cannot access admin endpoints."""
        # Create non-admin user and login
        email = 'nonadmin@example.com'
        password = 'testpass123'
        hashed_pw = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        users_collection.delete_one({'email': email})
        users_collection.insert_one({
            'email': email,
            'password': hashed_pw,
            'banned': False
        })

        try:
            # Logout admin
            self.client.post('/api/logout')

            # Login as non-admin
            login_response = self.client.post(
                '/api/login',
                data=json.dumps({'email': email, 'password': password}),
                content_type='application/json'
            )
            self.assertEqual(login_response.status_code, 200)

            # Try to access admin endpoint
            response = self.client.get('/api/admin/users')
            self.assertEqual(response.status_code, 403)
            data = json.loads(response.data)
            self.assertIn('Admin', data['error'])
        finally:
            users_collection.delete_one({'email': email})

    def test_unauthenticated_cannot_access_admin_endpoints(self):
        """Test that unauthenticated users cannot access admin endpoints."""
        self.client.post('/api/logout')
        response = self.client.get('/api/admin/users')
        self.assertEqual(response.status_code, 401)


class TestGetAllUsersEndpoint(AdminAPITestCase):
    """Tests for get-all-users endpoint."""

    def setUp(self):
        """Set up test users."""
        super().setUp()
        self.test_user1_email = 'testuser1@example.com'
        self.test_user2_email = 'testuser2@example.com'
        self.test_user1_id = self.create_test_user(self.test_user1_email)
        self.test_user2_id = self.create_test_user(self.test_user2_email)

    def tearDown(self):
        """Clean up test users."""
        super().tearDown()
        users_collection.delete_one({'email': self.test_user1_email})
        users_collection.delete_one({'email': self.test_user2_email})

    def test_get_all_users_success(self):
        """Test retrieving all users."""
        response = self.make_authenticated_request('GET', '/api/admin/users')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('users', data)
        self.assertIsInstance(data['users'], list)
        self.assertGreaterEqual(len(data['users']), 2)

    def test_get_all_users_excludes_passwords(self):
        """Test that password field is not included."""
        response = self.make_authenticated_request('GET', '/api/admin/users')
        data = json.loads(response.data)

        for user in data['users']:
            self.assertNotIn('password', user)

    def test_get_all_users_includes_user_fields(self):
        """Test that response includes necessary user fields."""
        response = self.make_authenticated_request('GET', '/api/admin/users')
        data = json.loads(response.data)

        user = data['users'][0]
        self.assertIn('_id', user)
        self.assertIn('email', user)

    def test_get_all_users_formats_timestamps(self):
        """Test that timestamps are formatted as strings."""
        response = self.make_authenticated_request('GET', '/api/admin/users')
        data = json.loads(response.data)

        user = data['users'][0]
        if 'created_at' in user:
            self.assertIsInstance(user['created_at'], str)


class TestBanUserEndpoint(AdminAPITestCase):
    """Tests for ban-user endpoint."""

    def setUp(self):
        """Set up test user."""
        super().setUp()
        self.test_user_email = 'bannedtest@example.com'
        self.test_user_id = self.create_test_user(self.test_user_email)

    def tearDown(self):
        """Clean up test user."""
        super().tearDown()
        users_collection.delete_one({'email': self.test_user_email})

    def test_ban_user_success(self):
        """Test banning a user."""
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/ban-user',
            {'user_id': self.test_user_id, 'reason': 'Violation of terms'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])

    def test_ban_user_updates_database(self):
        """Test that ban actually updates database."""
        self.make_authenticated_request(
            'POST',
            '/api/admin/ban-user',
            {'user_id': self.test_user_id, 'reason': 'Test ban'}
        )

        user = users_collection.find_one({'_id': ObjectId(self.test_user_id)})
        self.assertTrue(user['banned'])
        self.assertEqual(user['ban_reason'], 'Test ban')

    def test_ban_user_missing_user_id(self):
        """Test banning without user ID."""
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/ban-user',
            {'reason': 'No user ID'}
        )
        self.assertEqual(response.status_code, 400)

    def test_ban_user_invalid_user_id(self):
        """Test banning with invalid user ID format."""
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/ban-user',
            {'user_id': 'invalid-id', 'reason': 'Test'}
        )
        self.assertEqual(response.status_code, 400)

    def test_ban_nonexistent_user(self):
        """Test banning a user that doesn't exist."""
        fake_id = str(ObjectId())
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/ban-user',
            {'user_id': fake_id, 'reason': 'Does not exist'}
        )
        self.assertEqual(response.status_code, 404)

    def test_ban_user_with_default_reason(self):
        """Test banning with default reason."""
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/ban-user',
            {'user_id': self.test_user_id}
        )
        self.assertEqual(response.status_code, 200)

        user = users_collection.find_one({'_id': ObjectId(self.test_user_id)})
        self.assertIsNotNone(user['ban_reason'])

    def test_banned_user_cannot_login(self):
        """Test that banned users cannot login."""
        # Ban the user
        self.make_authenticated_request(
            'POST',
            '/api/admin/ban-user',
            {'user_id': self.test_user_id, 'reason': 'Banned for testing'}
        )

        # Logout
        self.client.post('/api/logout')

        # Try to login
        response = self.client.post(
            '/api/login',
            data=json.dumps({'email': self.test_user_email, 'password': 'testpass123'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 403)


class TestUnbanUserEndpoint(AdminAPITestCase):
    """Tests for unban-user endpoint."""

    def setUp(self):
        """Set up banned test user."""
        super().setUp()
        self.test_user_email = 'unbannedtest@example.com'
        self.test_user_id = self.create_test_user(self.test_user_email, banned=True)

    def tearDown(self):
        """Clean up test user."""
        super().tearDown()
        users_collection.delete_one({'email': self.test_user_email})

    def test_unban_user_success(self):
        """Test unbanning a user."""
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/unban-user',
            {'user_id': self.test_user_id}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])

    def test_unban_user_updates_database(self):
        """Test that unban actually updates database."""
        self.make_authenticated_request(
            'POST',
            '/api/admin/unban-user',
            {'user_id': self.test_user_id}
        )

        user = users_collection.find_one({'_id': ObjectId(self.test_user_id)})
        self.assertFalse(user['banned'])
        self.assertIsNone(user['ban_reason'])

    def test_unban_user_missing_user_id(self):
        """Test unbanning without user ID."""
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/unban-user',
            {}
        )
        self.assertEqual(response.status_code, 400)

    def test_unban_user_invalid_user_id(self):
        """Test unbanning with invalid user ID format."""
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/unban-user',
            {'user_id': 'invalid-id'}
        )
        self.assertEqual(response.status_code, 400)

    def test_unban_nonexistent_user(self):
        """Test unbanning a user that doesn't exist."""
        fake_id = str(ObjectId())
        response = self.make_authenticated_request(
            'POST',
            '/api/admin/unban-user',
            {'user_id': fake_id}
        )
        self.assertEqual(response.status_code, 404)

    def test_unbanned_user_can_login(self):
        """Test that unbanned users can login."""
        # Unban the user
        self.make_authenticated_request(
            'POST',
            '/api/admin/unban-user',
            {'user_id': self.test_user_id}
        )

        # Logout
        self.client.post('/api/logout')

        # Try to login
        response = self.client.post(
            '/api/login',
            data=json.dumps({'email': self.test_user_email, 'password': 'testpass123'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])


if __name__ == '__main__':
    unittest.main()
