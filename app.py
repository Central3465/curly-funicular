from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import re
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from bson.objectid import ObjectId

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
csrf = CSRFProtect(app)

REDIS_URL = os.getenv('REDIS_URL')
if REDIS_URL:
    storage_uri = REDIS_URL
else:
    storage_uri = 'memory://'

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=storage_uri,
    default_limits=[],
    in_memory_fallback_enabled=True
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

banned_ips = {}


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


def is_ip_banned(ip):
    if ip not in banned_ips:
        return False, None

    ban_data = banned_ips[ip]
    expires_at = ban_data['expires_at']

    if datetime.now() > expires_at:
        del banned_ips[ip]
        return False, None

    remaining = expires_at - datetime.now()
    return True, remaining


def ban_ip(ip, duration_hours, reason=''):
    expires_at = datetime.now() + timedelta(hours=duration_hours)
    banned_ips[ip] = {
        'ip_address': ip,
        'reason': reason,
        'banned_at': datetime.now(),
        'expires_at': expires_at
    }


def unban_ip(ip):
    if ip in banned_ips:
        del banned_ips[ip]


def validate_email(email):
    if not email or len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


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




from api import auth_bp, admin_bp, cipher_bp, conversion_bp, account_bp, csrf_bp

app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(cipher_bp)
app.register_blueprint(conversion_bp)
app.register_blueprint(account_bp)
app.register_blueprint(csrf_bp)

csrf_exempt_routes = [
    'auth.login',
    'auth.logout',
    'cipher.validate_cipher_endpoint',
    'cipher.decode_endpoint',
    'cipher.generate_cipher_endpoint',
    'cipher.encode_endpoint',
    'conversion.convert_base_endpoint',
    'conversion.ascii_to_base_endpoint',
    'conversion.base_to_ascii_endpoint',
    'account.request_account',
    'account.check_ip_ban',
    'csrf.get_csrf_token',
    'admin.get_all_users',
    'admin.ban_user',
    'admin.unban_user',
    'admin.add_user',
    'admin.ban_ip_endpoint',
    'admin.unban_ip_endpoint',
    'admin.get_banned_ips',
]

rate_limited_routes = [
    'auth.logout',
    'auth.get_user_data',
    'cipher.validate_cipher_endpoint',
    'cipher.decode_endpoint',
    'cipher.generate_cipher_endpoint',
    'cipher.encode_endpoint',
    'conversion.convert_base_endpoint',
    'conversion.ascii_to_base_endpoint',
    'conversion.base_to_ascii_endpoint',
    'account.request_account',
    'admin.get_all_users',
    'admin.ban_user',
    'admin.unban_user',
    'admin.add_user',
    'admin.ban_ip_endpoint',
    'admin.unban_ip_endpoint',
    'admin.get_banned_ips',
]

for route in csrf_exempt_routes:
    csrf.exempt(app.view_functions[route])

for route in rate_limited_routes:
    limiter.limit("3/minute")(app.view_functions[route])

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'True').lower() in ['true', '1', 't'])