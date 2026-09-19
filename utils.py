from flask import jsonify, session
from functools import wraps
from datetime import datetime, timedelta
from bson.objectid import ObjectId


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401
        return f(*args, **kwargs)
    return decorated_function
