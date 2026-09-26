#!/usr/bin/env python3
"""Script to add tier field to existing users in the database."""

import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    print('Error: DATABASE_URL environment variable not set')
    exit(1)

try:
    client = MongoClient(DATABASE_URL, serverSelectionTimeoutMS=5000)
    db = client['cipher_app']
    users_collection = db['users']

    # Find all users without a tier field
    users_without_tier = users_collection.find({'tier': {'$exists': False}})
    count = users_collection.count_documents({'tier': {'$exists': False}})

    if count == 0:
        print('✓ All users already have tier field set')
    else:
        # Add tier field with default value (0) to all users without it
        result = users_collection.update_many(
            {'tier': {'$exists': False}},
            {'$set': {'tier': 0}}  # 0 = default tier
        )
        print(f'✓ Migration completed successfully!')
        print(f'  Users updated: {result.modified_count}')

    client.close()

except Exception as e:
    print(f'Error: {e}')
    exit(1)
