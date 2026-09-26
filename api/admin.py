from flask import jsonify, session, request
from functools import wraps
from datetime import datetime
from bson.objectid import ObjectId
import bcrypt
import ipaddress
from api import admin_bp


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app import users_collection

        if not session.get('user_id'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401

        user = users_collection.find_one({'_id': ObjectId(session.get('user_id'))}) if users_collection is not None else None
        if not user or not user.get('isAdmin', False):
            return jsonify({'error': 'Admin access required'}), 403

        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/api/admin/users', methods=['GET'])
@require_admin
def get_all_users():
    from app import users_collection

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


@admin_bp.route('/api/admin/ban-user', methods=['POST'])
@require_admin
def ban_user():
    from app import users_collection, validate_email

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


@admin_bp.route('/api/admin/unban-user', methods=['POST'])
@require_admin
def unban_user():
    from app import users_collection

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


@admin_bp.route('/api/admin/add-user', methods=['POST'])
@require_admin
def add_user():
    from app import users_collection, validate_email
    from utils import initialize_usage_limits, TIER_DEFAULT, TIER_TRUSTED, TIER_PRO, TIER_SUPERUSER

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    isadmin = data.get('isAdmin', False)
    tier = data.get('tier', TIER_DEFAULT)

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if tier not in [TIER_DEFAULT, TIER_TRUSTED, TIER_PRO, TIER_SUPERUSER]:
        return jsonify({'error': 'Invalid tier'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    new_user = {
        'email': email,
        'password': hashed_password,
        'isAdmin': isadmin,
        'tier': tier,
        'created_at': datetime.now(),
        'banned': False
    }

    try:
        result = users_collection.insert_one(new_user)
        initialize_usage_limits(str(result.inserted_id))
        return jsonify({'success': True, 'message': 'User added successfully', 'user_id': str(result.inserted_id)})
    except Exception as e:
        if 'duplicate' in str(e).lower():
            return jsonify({'error': 'Email already exists'}), 409
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/api/admin/ban-ip', methods=['POST'])
@require_admin
def ban_ip_endpoint():
    from app import ban_ip

    data = request.get_json()
    ip_address = data.get('ip_address', '').strip()
    duration = data.get('duration', 24)
    reason = data.get('reason', '')

    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400

    if not is_valid_ip(ip_address):
        return jsonify({'error': 'Invalid IP address format'}), 400

    try:
        duration = int(duration)
        if duration < 1:
            return jsonify({'error': 'Duration must be at least 1 hour'}), 400
    except ValueError:
        return jsonify({'error': 'Duration must be a number'}), 400

    ban_ip(ip_address, duration, reason)
    return jsonify({'success': True, 'message': f'IP {ip_address} banned for {duration} hours'})


@admin_bp.route('/api/admin/unban-ip', methods=['POST'])
@require_admin
def unban_ip_endpoint():
    from app import unban_ip

    data = request.get_json()
    ip_address = data.get('ip_address', '').strip()

    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400

    if not is_valid_ip(ip_address):
        return jsonify({'error': 'Invalid IP address format'}), 400

    unban_ip(ip_address)
    return jsonify({'success': True, 'message': f'IP {ip_address} has been unbanned'})


@admin_bp.route('/api/admin/update-tier', methods=['POST'])
@require_admin
def update_tier():
    from app import users_collection
    from utils import TIER_DEFAULT, TIER_TRUSTED, TIER_PRO, TIER_SUPERUSER

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    data = request.get_json()
    user_id = data.get('user_id')
    tier = data.get('tier')

    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400

    if tier is None or tier not in [TIER_DEFAULT, TIER_TRUSTED, TIER_PRO, TIER_SUPERUSER]:
        return jsonify({'error': 'Invalid tier'}), 400

    try:
        object_id = ObjectId(user_id)
    except Exception:
        return jsonify({'error': 'Invalid user ID format'}), 400

    user = users_collection.find_one({'_id': object_id})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    result = users_collection.update_one(
        {'_id': object_id},
        {'$set': {'tier': tier}}
    )

    if result.modified_count == 0:
        return jsonify({'error': 'Failed to update tier'}), 500

    return jsonify({'success': True, 'message': f'User tier updated to {tier}'})


@admin_bp.route('/api/admin/banned-ips', methods=['GET'])
@require_admin
def get_banned_ips():
    from app import get_all_banned_ips

    bans = get_all_banned_ips()
    return jsonify({'banned_ips': bans})
