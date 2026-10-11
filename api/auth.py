from flask import jsonify, session, request
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from bson.errors import InvalidId
import bcrypt
from api import auth_bp
from utils import require_auth

# Checked when the email is unknown so that unknown and known accounts take similar time to respond
DUMMY_PASSWORD_HASH = bcrypt.hashpw(b'dummy-password', bcrypt.gensalt())


@auth_bp.route('/api/login', methods=['POST'])
def login():
    from app import users_collection, is_ip_blocked, get_lockout_time_remaining, record_failed_attempt, clear_login_attempts, get_client_ip, get_login_attempt_count, MAX_LOGIN_ATTEMPTS, is_ip_banned

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    client_ip = get_client_ip()

    is_banned, remaining = is_ip_banned(client_ip)
    if is_banned:
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        return jsonify({
            'success': False,
            'error': f'This IP address has been banned. Please try again in {hours}h {minutes}m.'
        }), 429

    if is_ip_blocked(client_ip):
        time_remaining = get_lockout_time_remaining(client_ip)
        return jsonify({
            'success': False,
            'error': f'Too many failed attempts. You are temporarily blocked for {time_remaining}. Please try again later.'
        }), 429

    data = request.get_json(silent=True) or {}
    email = str(data.get('email') or '').strip().lower()
    password = str(data.get('password') or '')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = users_collection.find_one({'email': email})

    stored_hash = user.get('password') if user else None
    if stored_hash:
        password_ok = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    else:
        bcrypt.checkpw(password.encode('utf-8'), DUMMY_PASSWORD_HASH)
        password_ok = False

    if not user or not password_ok:
        record_failed_attempt(client_ip)
        if get_login_attempt_count(client_ip) >= MAX_LOGIN_ATTEMPTS:
            time_remaining = get_lockout_time_remaining(client_ip)
            return jsonify({
                'error': f'Too many failed attempts. You are now blocked for {time_remaining}.'
            }), 429
        return jsonify({'error': 'Invalid email or password.'}), 401

    if user.get('banned'):
        return jsonify({'error': 'Your account has been restricted.'}), 403

    #if user.get('ip_address') != client_ip:
    #    return jsonify({
    #        'error': 'IP address mismatch. Please use the same IP address you registered with. This is a security measure to prevent unauthorized access.'
    #    }), 400

    clear_login_attempts(client_ip)
    session.clear()
    session['user_id'] = str(user['_id'])
    session['email'] = user['email']
    session['isAdmin'] = user.get('isAdmin', False)
    created_at = user.get('created_at')
    is_new_account = isinstance(created_at, datetime) and datetime.now() - created_at < timedelta(days=3)

    return jsonify({'success': True, 'message': 'Login successful', 'is_new_account': is_new_account}), 200


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

    try:
        user_oid = ObjectId(session.get('user_id'))
    except (InvalidId, TypeError):
        return jsonify({'error': 'Unauthorized. Please log in.'}), 401

    user = users_collection.find_one({'_id': user_oid})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    created_at = user.get('created_at')
    if isinstance(created_at, datetime):
        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')
    elif created_at:
        created_at = str(created_at)
    else:
        created_at = 'Unknown'

    tier = user.get('tier', 0)
    tier_names = {
        0: 'Default',
        1: 'Trusted',
        2: 'Pro',
        3: 'Superuser'
    }

    return jsonify({
        'email': user['email'],
        'created_at': created_at,
        'banned': user.get('banned', False),
        'tier': tier,
        'tier_name': tier_names.get(tier, 'Unknown')
    })
