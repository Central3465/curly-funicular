from flask import jsonify, session, request
from datetime import datetime
from bson.objectid import ObjectId
import bcrypt
from api import auth_bp
from utils import require_auth


@auth_bp.route('/api/login', methods=['POST'])
def login():
    from app import users_collection, is_ip_blocked, get_lockout_time_remaining, record_failed_attempt, clear_login_attempts, get_client_ip, login_attempts, MAX_LOGIN_ATTEMPTS

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    client_ip = get_client_ip()

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

    user = users_collection.find_one({'email': email})

    if not user:
        record_failed_attempt(client_ip)
        return jsonify({'error': 'Invalid email or password'}), 401

    if user.get('banned'):
        return jsonify({'error': 'Your account has been banned. Contact support for assistance.'}), 403

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

    clear_login_attempts(client_ip)
    session['user_id'] = str(user['_id'])
    session['email'] = user['email']

    return jsonify({'success': True, 'message': 'Login successful'})


@auth_bp.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@auth_bp.route('/api/user-data', methods=['GET'])
@require_auth
def get_user_data():
    from app import users_collection

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
