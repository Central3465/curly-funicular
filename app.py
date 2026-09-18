from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cipher import decode_message, validate_cipher, encode_message, create_random_cipher, convert_base, ascii_to_base, base_to_ascii
import os
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import requests
import re
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from bson.objectid import ObjectId
import bcrypt

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
csrf = CSRFProtect(app)

REDIS_URL = os.getenv('REDIS_URL')
if REDIS_URL:
    storage_uri = REDIS_URL
else:
    storage_uri = 'file:///tmp/flask_limiter'

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=storage_uri,
    default_limits=[]
)

DATABASE_URL = os.getenv('DATABASE_URL')

# MongoDB connection
try:
    client = MongoClient(DATABASE_URL, serverSelectionTimeoutMS=5000)
    db = client['cipher_app']
    users_collection = db['users']
    users_collection.create_index('email', unique=True)
except ConnectionFailure as e:
    print(f"Failed to connect to MongoDB: {e}")
    db = None
    users_collection = None

login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(hours=24)

access_requests = {}
ACCESS_REQUEST_LIMIT = 1
ACCESS_REQUEST_WINDOW = timedelta(minutes=1)


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def is_ip_blocked(ip):
    if ip not in login_attempts:
        return False

    attempt_data = login_attempts[ip]
    last_attempt_time = attempt_data['last_attempt']
    failed_count = attempt_data['count']

    # Reset if 24 hours have passed
    if datetime.now() - last_attempt_time > LOCKOUT_DURATION:
        del login_attempts[ip]
        return False

    return failed_count >= MAX_LOGIN_ATTEMPTS


def get_lockout_time_remaining(ip):
    if ip not in login_attempts:
        return None

    last_attempt_time = login_attempts[ip]['last_attempt']
    lockout_end = last_attempt_time + LOCKOUT_DURATION
    remaining = lockout_end - datetime.now()

    if remaining.total_seconds() > 0:
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        return f"{hours}h {minutes}m"
    return None


def record_failed_attempt(ip):
    if ip in login_attempts:
        login_attempts[ip]['count'] += 1
        login_attempts[ip]['last_attempt'] = datetime.now()
    else:
        login_attempts[ip] = {
            'count': 1,
            'last_attempt': datetime.now()
        }


def clear_login_attempts(ip):
    if ip in login_attempts:
        del login_attempts[ip]


def can_make_access_request(ip):
    if ip not in access_requests:
        return True, None

    last_request_time = access_requests[ip]
    time_since_last_request = datetime.now() - last_request_time

    if time_since_last_request < ACCESS_REQUEST_WINDOW:
        wait_time = int((ACCESS_REQUEST_WINDOW - time_since_last_request).total_seconds())
        return False, wait_time
    else:
        del access_requests[ip]
        return True, None


def record_access_request(ip):
    access_requests[ip] = datetime.now()


def validate_email(email):
    if not email or len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401

        user = users_collection.find_one({'_id': ObjectId(session.get('user_id'))}) if users_collection is not None else None
        if not user or not user.get('isAdmin', False):
            return jsonify({'error': 'Admin access required'}), 403

        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    if session.get('user_id'):
        return render_template('index.html', logged_in=True)
    return render_template('index.html', logged_in=False)

@app.route('/api/csrf-token', methods=['GET'])
@csrf.exempt
@limiter.limit("3/minute")
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

@app.route('/credits')
def credits():
    return render_template('credits.html')

@app.route('/version')
def request_access():
    return render_template('version.html')

@app.route('/register')
def register_page():
    if session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login')
def login_page():
    if session.get('user_id'):
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/settings')
def settings_page():
    if not session.get('user_id'):
        return redirect(url_for('login_page'))
    return render_template('settings.html')

@app.route('/admin')
@require_admin
def admin_page():
    return render_template('admin.html')


@app.route('/api/register', methods=['POST'])
@csrf.exempt
@limiter.limit("3/minute")
def register():
    return jsonify({'error': 'Registration is disabled. Please email contact@bai.studio to request an account.'}), 403


@app.route('/api/login', methods=['POST'])
@csrf.exempt
def login():
    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500
    
    client_ip = get_client_ip()
    
    # Check if IP is blocked
    if is_ip_blocked(client_ip):
        time_remaining = get_lockout_time_remaining(client_ip)
        return jsonify({
            'success': False,
            'error': f'Too many failed attempts. Your IP is temporarily blocked for {time_remaining}. Please try again later.'
        }), 429
    
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    # Find user
    user = users_collection.find_one({'email': email})
    
    if not user:
        record_failed_attempt(client_ip)
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Check if user is banned
    if user.get('banned'):
        return jsonify({'error': 'Your account has been banned. Contact support for assistance.'}), 403
    
    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        record_failed_attempt(client_ip)
        attempt_data = login_attempts[client_ip]
        remaining_attempts = MAX_LOGIN_ATTEMPTS - attempt_data['count']
        
        if remaining_attempts > 0:
            return jsonify({
                'error': f'Invalid email or password. {remaining_attempts} attempt{"s" if remaining_attempts != 1 else ""} remaining.'
            }), 401
        else:
            time_remaining = get_lockout_time_remaining(client_ip)
            return jsonify({
                'error': f'Too many failed attempts. Your IP is now blocked for {time_remaining}.'
            }), 429
    
    # Successful login
    clear_login_attempts(client_ip)
    session['user_id'] = str(user['_id'])
    session['email'] = user['email']
    
    return jsonify({'success': True, 'message': 'Login successful'})


@app.route('/api/logout', methods=['POST'])
@limiter.limit("3/minute")
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/user-data', methods=['GET'])
@require_auth
@limiter.limit("3/minute")
def get_user_data():
    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    user = users_collection.find_one({'_id': ObjectId(session.get('user_id'))})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    created_at = user.get('created_at')
    if isinstance(created_at, datetime):
        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')
    elif created_at:
        created_at = str(created_at)
    else:
        created_at = 'Unknown'

    return jsonify({
        'email': user['email'],
        'created_at': created_at,
        'banned': user.get('banned', False)
    })


@app.route('/api/admin/users', methods=['GET'])
@require_admin
@limiter.limit("3/minute")
def get_all_users():
    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    users = list(users_collection.find({}, {'password': 0}))

    for user in users:
        user['_id'] = str(user['_id'])
        created_at = user.get('created_at')
        if isinstance(created_at, datetime):
            user['created_at'] = created_at.strftime('%Y-%m-%d %H:%M:%S')
        elif created_at:
            user['created_at'] = str(created_at)

    return jsonify({'users': users})


@app.route('/api/admin/ban-user', methods=['POST'])
@require_admin
@limiter.limit("3/minute")
def ban_user():
    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    data = request.get_json()
    user_id = data.get('user_id')
    reason = data.get('reason', 'No reason provided')

    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400

    try:
        object_id = ObjectId(user_id)
    except Exception:
        return jsonify({'error': 'Invalid user ID format'}), 400

    # Don't allow banning the admin
    user = users_collection.find_one({'_id': object_id})
    if user and user.get('isAdmin', False):
        return jsonify({'error': 'Cannot ban admin account'}), 403

    result = users_collection.update_one(
        {'_id': object_id},
        {'$set': {'banned': True, 'ban_reason': reason}}
    )

    if result.modified_count == 0:
        return jsonify({'error': 'User not found or already banned'}), 404

    return jsonify({'success': True, 'message': 'User has been banned'})


@app.route('/api/admin/unban-user', methods=['POST'])
@require_admin
@limiter.limit("3/minute")
def unban_user():
    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    data = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400

    try:
        object_id = ObjectId(user_id)
    except Exception:
        return jsonify({'error': 'Invalid user ID format'}), 400

    result = users_collection.update_one(
        {'_id': object_id},
        {'$set': {'banned': False, 'ban_reason': None}}
    )

    if result.modified_count == 0:
        return jsonify({'error': 'User not found or not banned'}), 404

    return jsonify({'success': True, 'message': 'User has been unbanned'})


@app.route('/api/validate-cipher', methods=['POST'])
@require_auth
@limiter.limit("3/minute")
def validate_cipher_endpoint():
    data = request.get_json()
    cipher_input = data.get('cipher', '')

    is_valid, result = validate_cipher(cipher_input)

    if is_valid:
        return jsonify({'valid': True, 'cipher': result})
    else:
        return jsonify({'valid': False, 'error': result})


@app.route('/api/decode', methods=['POST'])
@require_auth
@limiter.limit("3/minute")
def decode_endpoint():
    data = request.get_json()

    cipher_input = data.get('cipher', '')
    encrypted_message = data.get('message', '')
    key = data.get('key', '')

    if not key:
        return jsonify({'error': 'Key cannot be empty'}), 400

    is_valid, cipher_or_error = validate_cipher(cipher_input)
    if not is_valid:
        return jsonify({'error': cipher_or_error}), 400

    try:
        decoded = decode_message(encrypted_message, cipher_or_error, key)
        return jsonify({'decoded': decoded})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/generate-cipher', methods=['POST'])
@require_auth
@limiter.limit("3/minute")
def generate_cipher_endpoint():
    try:
        cipher = create_random_cipher()
        return jsonify({'cipher': cipher, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/encode', methods=['POST'])
@require_auth
@limiter.limit("3/minute")
def encode_endpoint():
    data = request.get_json()

    cipher_input = data.get('cipher', '')
    message = data.get('message', '')
    key = data.get('key', '')

    if not key:
        return jsonify({'error': 'Key cannot be empty'}), 400

    is_valid, cipher_or_error = validate_cipher(cipher_input)
    if not is_valid:
        return jsonify({'error': cipher_or_error}), 400

    try:
        encrypted = encode_message(message, cipher_or_error, key)
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/convert-base', methods=['POST'])
@require_auth
@limiter.limit("3/minute")
def convert_base_endpoint():
    data = request.get_json()
    number = data.get('number', '').strip()
    from_base = data.get('from_base')
    to_base = data.get('to_base')

    if not number:
        return jsonify({'error': 'Number cannot be empty'}), 400

    try:
        from_base = int(from_base)
        to_base = int(to_base)

        if not (2 <= from_base <= 36) or not (2 <= to_base <= 36):
            return jsonify({'error': 'Base must be between 2 and 36'}), 400

        result = convert_base(number, from_base, to_base)
        return jsonify({'result': result, 'success': True})
    except ValueError as e:
        return jsonify({'error': f'Invalid number for base {from_base}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ascii-to-base', methods=['POST'])
@require_auth
@limiter.limit("3/minute")
def ascii_to_base_endpoint():
    data = request.get_json()
    text = data.get('text', '')
    base = data.get('base')

    if not text:
        return jsonify({'error': 'Text cannot be empty'}), 400

    try:
        base = int(base)

        if not (2 <= base <= 36):
            return jsonify({'error': 'Base must be between 2 and 36'}), 400

        result = ascii_to_base(text, base)
        return jsonify({'result': result, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/base-to-ascii', methods=['POST'])
@require_auth
@limiter.limit("3/minute")
def base_to_ascii_endpoint():
    data = request.get_json()
    numbers = data.get('numbers', '').strip()
    base = data.get('base')

    if not numbers:
        return jsonify({'error': 'Numbers cannot be empty'}), 400

    try:
        base = int(base)

        if not (2 <= base <= 36):
            return jsonify({'error': 'Base must be between 2 and 36'}), 400

        result = base_to_ascii(numbers, base)
        return jsonify({'result': result, 'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)