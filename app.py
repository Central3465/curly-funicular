from flask import Flask, render_template, request, jsonify, session
from cipher import decode_message, validate_cipher, encode_message, create_random_cipher, convert_base, ascii_to_base, base_to_ascii
import os
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import requests
import re

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
PASSWORD = os.getenv('PASSWORD', '')
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', '')

# Rate limiting for password attempts
failed_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(hours=24)

# Rate limiting for access requests
access_requests = {}
ACCESS_REQUEST_LIMIT = 1
ACCESS_REQUEST_WINDOW = timedelta(minutes=1)


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
    if not email.endswith('@bai.studio'):
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@bai\.studio$'
    return bool(re.match(pattern, email))


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


@app.route('/version')
def request_access():
    return render_template('version.html')


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


@app.route('/api/request-access', methods=['POST'])
def request_access_endpoint():
    client_ip = get_client_ip()

    # Rate limiting check
    can_request, wait_time = can_make_access_request(client_ip)
    if not can_request:
        return jsonify({
            'error': f'You can only submit one access request every 5 minutes. Please try again in {wait_time} seconds.'
        }), 429

    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    description = data.get('description', '').strip()

    # Validate input
    if not name or len(name) > 100:
        return jsonify({'error': 'Invalid name'}), 400

    if not email or len(email) > 254:
        return jsonify({'error': 'Invalid email'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Email must be from the bai.studio domain'}), 400

    if not description or len(description) < 10 or len(description) > 1000:
        return jsonify({'error': 'Description must be between 10 and 1000 characters'}), 400

    # Record the request for rate limiting
    record_access_request(client_ip)

    # Send to Discord webhook
    try:
        embed = {
            'title': '🔐 New Access Request',
            'description': description,
            'color': 4294144,
            'fields': [
                {
                    'name': 'Name',
                    'value': name,
                    'inline': False
                },
                {
                    'name': 'Email',
                    'value': email,
                    'inline': False
                },
                {
                    'name': 'Submitted At',
                    'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'inline': False
                }
            ]
        }

        payload = {
            'embeds': [embed]
        }

        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)

        if response.status_code != 204:
            return jsonify({'error': 'Failed to send request. Please try again later.'}), 500

        return jsonify({'success': True, 'message': 'Access request submitted successfully'}), 200

    except requests.exceptions.RequestException:
        return jsonify({'error': 'Failed to send request. Please try again later.'}), 500
    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred'}), 500


@app.route('/api/convert-base', methods=['POST'])
@require_auth
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