from flask import jsonify, request, url_for, session
from datetime import date
from flask_mail import Message
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import requests
import os
import secrets
import bcrypt
from api import account_bp
from utils import require_auth, hash_api_key

def is_over_13(birthday_str) -> bool:
    if not isinstance(birthday_str, str):
        raise ValueError('Birthday must be a date string')
    birthday = date.fromisoformat(birthday_str.strip())
    today = date.today()
    age = today.year - birthday.year - (
        (today.month, today.day) < (birthday.month, birthday.day)
    )
    return age >= 13

@account_bp.route('/api/register', methods=['POST'])
def register():
    from app import users_collection, validate_email, get_client_ip

    client_ip = get_client_ip()

    data = request.get_json()
    full_name = data.get('fullName', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirmPassword', '')
    #birthday = data.get('birthday', '')

    #user = users_collection.find_one({'email': email})
    #if user and user.get('ip_address') != client_ip:
    #    return jsonify({
    #        'error': 'IP address mismatch. Please use the same IP address you registered with. This is a security measure to prevent unauthorized access.'
    #    }), 400

    #try:
    #    if not is_over_13(birthday):
    #        return jsonify({"error": "You must be 13 or older to register in compliance with our privacy policy."}), 403
    #except ValueError:
    #    return jsonify({"error": "Invalid date."}), 400

    if not full_name or not email or not password or not confirm_password:
        return jsonify({'error': 'All fields are required'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'Email already registered'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user_doc = {
        'email': email,
        'password': hashed_password,
        'full_name': full_name,
        'created_at': datetime.now(),
        'token_expires_at': datetime.now() + timedelta(hours=24),
        'banned': False,
        'tier': 0,
        'api_key_created_at': None,
        'ip_address': client_ip,
    }

    users_collection.insert_one(user_doc)

    return jsonify({'success': True, 'message': 'Account created.'}), 201


@account_bp.route('/api/check-ip-ban', methods=['GET'])
def check_ip_ban():
    from app import get_client_ip, is_ip_banned

    client_ip = get_client_ip()
    is_banned, remaining = is_ip_banned(client_ip)

    if is_banned:
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        return jsonify({
            'banned': True,
            'remaining_time': f"{hours}h {minutes}m",
            'message': f'This IP address has been banned. Please try again in {hours}h {minutes}m.'
        })

    return jsonify({'banned': False})


@account_bp.route('/api/api-key-status', methods=['GET'])
@require_auth
def api_key_status():
    from app import users_collection

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    user = users_collection.find_one({'_id': ObjectId(session.get('user_id'))})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    created_at = user.get('api_key_created_at')
    if isinstance(created_at, datetime):
        created_at = created_at.strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({'has_key': bool(user.get('api_key_hash')), 'created_at': created_at})


@account_bp.route('/api/generate-api-key', methods=['POST'])
@require_auth
def generate_api_key():
    from app import users_collection

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    api_key = f"sk_{secrets.token_urlsafe(32)}"

    users_collection.update_one(
        {'_id': ObjectId(session.get('user_id'))},
        {'$set': {
            'api_key_hash': hash_api_key(api_key),
            'api_key_created_at': datetime.now()
        }}
    )

    return jsonify({'success': True, 'api_key': api_key})

@account_bp.route('/api/delete-account', methods=['POST'])
@require_auth
def delete_account():
    from app import users_collection

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    users_collection.delete_one({'_id': ObjectId(user_id)})

    session.clear()

    return jsonify({'success': True, 'message': 'Account deleted.'})