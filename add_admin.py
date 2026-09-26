#!/usr/bin/env python3
"""Script to add a test admin user to the database."""

import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from datetime import datetime
import bcrypt

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    print('Error: DATABASE_URL environment variable not set')
    exit(1)

try:
    client = MongoClient(DATABASE_URL, serverSelectionTimeoutMS=5000)
    db = client['cipher_app']
    users_collection = db['users']

    # Ensure email index exists
    users_collection.create_index('email', unique=True)

    # Create admin user
    admin_email = str(input('Enter admin email: ')).strip()
    admin_password = str(input('Enter admin password: ')).strip()

    # Hash password with bcrypt
    hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    admin_user = {
        'email': admin_email,
        'password': hashed_password,
        'isAdmin': True,
        'tier': 3,  # Superuser tier for admin
        'created_at': datetime.now(),
        'banned': False
    }

    try:
        result = users_collection.insert_one(admin_user)
        print(f'✓ Admin user created successfully!')
        print(f'  Email: {admin_email}')
        print(f'  Password: {admin_password}')
        print(f'  User ID: {result.inserted_id}')
    except DuplicateKeyError:
        print(f'✗ Admin user with email {admin_email} already exists')
        exit(1)

    client.close()

except Exception as e:
    print(f'Error: {e}')
    exit(1)
