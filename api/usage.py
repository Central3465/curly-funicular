from flask import jsonify, session
from api import usage_bp
from utils import require_auth, get_usage_limits
from datetime import datetime
from bson.objectid import ObjectId


@usage_bp.route('/api/usage-limits', methods=['GET'])
@require_auth
def get_usage():
    from app import users_collection

    if users_collection is None:
        return jsonify({'error': 'Database connection failed'}), 500

    user_id = session.get('user_id')
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    limits = get_usage_limits(user_id)

    if not limits:
        return jsonify({'error': 'Usage limits not initialized'}), 500

    session_limit = limits.get('session_limit', {})
    weekly_limit = limits.get('weekly_limit', {})

    session_reset_at = session_limit.get('reset_at')
    if isinstance(session_reset_at, str):
        session_reset_at = datetime.fromisoformat(session_reset_at)

    weekly_reset_at = weekly_limit.get('reset_at')
    if isinstance(weekly_reset_at, str):
        weekly_reset_at = datetime.fromisoformat(weekly_reset_at)

    session_percentage = int((session_limit.get('count', 0) / session_limit.get('max', 100)) * 100)
    weekly_percentage = int((weekly_limit.get('count', 0) / weekly_limit.get('max', 500)) * 100)

    return jsonify({
        'session_limit': {
            'current': session_limit.get('count', 0),
            'max': session_limit.get('max', 100),
            'percentage': min(session_percentage, 100),
            'reset_at': session_reset_at.isoformat() if session_reset_at else None
        },
        'weekly_limit': {
            'current': weekly_limit.get('count', 0),
            'max': weekly_limit.get('max', 500),
            'percentage': min(weekly_percentage, 100),
            'reset_at': weekly_reset_at.isoformat() if weekly_reset_at else None
        }
    })
