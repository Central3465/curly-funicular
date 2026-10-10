from flask import jsonify, request, url_for, session
from flask_mail import Message
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import requests
import os
import secrets
import bcrypt
from api import account_bp
from utils import require_auth, hash_api_key


def send_verification_email(mail, email, full_name, verification_token):
    verification_link = f"{request.host_url.rstrip('/')}/verify-email?token={verification_token}"

    msg = Message(
        subject='Verify Your Email - Cipher App',
        recipients=[email],
        html=f"""
        <html>
            <body>
                <h2>Welcome, {full_name}!</h2>
                <p>Thank you for registering with Cipher App. Please verify your email address to complete your registration.</p>
                <p>
                    <a href="{verification_link}" style="background-color: #4682B4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Verify Email
                    </a>
                </p>
                <p>Or copy this link: {verification_link}</p>
                <p>This link will expire in 24 hours.</p>
                <p>If you did not register for this account, please ignore this email.</p>
            </body>
        </html>
        """,
        sender=os.getenv('EMAIL_USER', 'noreply@example.com')
    )
    mail.send(msg)


@account_bp.route('/api/register', methods=['POST'])
def register():
    from app import users_collection, validate_email, mail

    data = request.get_json()
    full_name = data.get('fullName', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirmPassword', '')

    if not full_name or not email or not password or not confirm_password:
        return jsonify({'error': 'All fields are required'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400

    valid_domains = ['@bai.studio', '@travelut.app']
    if not any(email.endswith(domain) for domain in valid_domains):
        return jsonify({'error': 'No permissions'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'Email already registered'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    verification_token = secrets.token_urlsafe(32)
    verification_token_hash = bcrypt.hashpw(verification_token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user_doc = {
        'email': email,
        'password': hashed_password,
        'full_name': full_name,
        'created_at': datetime.now(),
        'verified': False,
        'verification_token': verification_token_hash,
        'token_expires_at': datetime.now() + timedelta(hours=24),
        'banned': False,
        'tier': 0,
    }

    users_collection.insert_one(user_doc)

    try:
        send_verification_email(mail, email, full_name, verification_token)
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return jsonify({'error': 'Account created but failed to send verification email. Please contact support.'}), 500

    return jsonify({'success': True, 'message': 'Account created. Check your email to verify.'}), 201


@account_bp.route('/api/verify-email', methods=['POST'])
def verify_email():
    from app import users_collection

    data = request.get_json()
    token = data.get('token', '')

    if not token:
        return jsonify({'error': 'Verification token is required'}), 400

    users = users_collection.find({'verified': False})
    user = None

    for u in users:
        if u.get('verification_token') and bcrypt.checkpw(token.encode('utf-8'), u['verification_token'].encode('utf-8')):
            user = u
            break

    if not user:
        return jsonify({'error': 'Invalid or expired verification token'}), 401

    if user.get('token_expires_at') and user['token_expires_at'] < datetime.now():
        return jsonify({'error': 'Verification token has expired'}), 400

    users_collection.update_one(
        {'_id': user['_id']},
        {
            '$set': {
                'verified': True,
                'verification_token': None,
                'token_expires_at': None
            }
        }
    )

    return jsonify({'success': True, 'message': 'Email verified successfully'}), 200


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
