from flask import Flask, render_template, request, jsonify, session
from cipher import decode_message, validate_cipher, encode_message, create_random_cipher
import os
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
PASSWORD = os.getenv('PASSWORD', '')

# Rate limiting for password attempts
failed_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(hours=24)


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def is_ip_blocked(ip):
    if ip not in failed_attempts:
        return False

    attempt_data = failed_attempts[ip]
    last_attempt_time = attempt_data['last_attempt']
    failed_count = attempt_data['count']

    # Reset if 24 hours have passed
    if datetime.now() - last_attempt_time > LOCKOUT_DURATION:
        del failed_attempts[ip]
        return False

    return failed_count >= MAX_ATTEMPTS


def get_lockout_time_remaining(ip):
    if ip not in failed_attempts:
        return None

    last_attempt_time = failed_attempts[ip]['last_attempt']
    lockout_end = last_attempt_time + LOCKOUT_DURATION
    remaining = lockout_end - datetime.now()

    if remaining.total_seconds() > 0:
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        return f"{hours}h {minutes}m"
    return None


def record_failed_attempt(ip):
    if ip in failed_attempts:
        failed_attempts[ip]['count'] += 1
        failed_attempts[ip]['last_attempt'] = datetime.now()
    else:
        failed_attempts[ip] = {
            'count': 1,
            'last_attempt': datetime.now()
        }


def clear_failed_attempts(ip):
    if ip in failed_attempts:
        del failed_attempts[ip]


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({'error': 'Unauthorized. Please enter the password.'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/check-password', methods=['POST'])
def check_password():
    client_ip = get_client_ip()

    # Check if IP is blocked
    if is_ip_blocked(client_ip):
        time_remaining = get_lockout_time_remaining(client_ip)
        return jsonify({
            'valid': False,
            'error': f'Too many failed attempts. Your IP is temporarily blocked for {time_remaining}. Please try again later.'
        }), 429

    data = request.get_json()
    password_input = data.get('password', '')

    if password_input == PASSWORD:
        session['authenticated'] = True
        clear_failed_attempts(client_ip)
        return jsonify({'valid': True})
    else:
        record_failed_attempt(client_ip)
        attempt_data = failed_attempts[client_ip]
        remaining_attempts = MAX_ATTEMPTS - attempt_data['count']

        if remaining_attempts > 0:
            return jsonify({
                'valid': False,
                'error': f'Invalid password. {remaining_attempts} attempt{"s" if remaining_attempts != 1 else ""} remaining.'
            }), 401
        else:
            time_remaining = get_lockout_time_remaining(client_ip)
            return jsonify({
                'valid': False,
                'error': f'Too many failed attempts. Your IP is now blocked for {time_remaining}.'
            }), 429


@app.route('/api/validate-cipher', methods=['POST'])
@require_auth
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
def generate_cipher_endpoint():
    try:
        cipher = create_random_cipher()
        return jsonify({'cipher': cipher, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/encode', methods=['POST'])
@require_auth
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


if __name__ == '__main__':
    app.run(debug=True)