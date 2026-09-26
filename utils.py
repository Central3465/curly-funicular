from flask import jsonify, session
from functools import wraps
from datetime import datetime, timedelta
from bson.objectid import ObjectId


# Tier constants
TIER_DEFAULT = 0
TIER_TRUSTED = 1
TIER_PRO = 2
TIER_SUPERUSER = 3

# Base limits for default tier (0)
BASE_SESSION_LIMIT = 100
BASE_WEEKLY_LIMIT = 500

# Tier multipliers
TIER_MULTIPLIERS = {
    TIER_DEFAULT: 1.0,
    TIER_TRUSTED: 1.5,
    TIER_PRO: 2.0,
    TIER_SUPERUSER: float('inf')  # unlimited
}


def get_tier_limits(tier):
    """Get session and weekly limits based on user tier."""
    multiplier = TIER_MULTIPLIERS.get(tier, 1.0)

    if tier == TIER_SUPERUSER:
        return float('inf'), float('inf')

    session_limit = int(BASE_SESSION_LIMIT * multiplier)
    weekly_limit = int(BASE_WEEKLY_LIMIT * multiplier)

    return session_limit, weekly_limit


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401
        return f(*args, **kwargs)
    return decorated_function


def track_usage(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app import users_collection

        if not session.get('user_id') or users_collection is None:
            return f(*args, **kwargs)

        user_id = session.get('user_id')
        user = users_collection.find_one({'_id': ObjectId(user_id)})

        if not user:
            return f(*args, **kwargs)

        result = f(*args, **kwargs)

        if isinstance(result, tuple) and len(result) >= 2:
            status_code = result[1] if len(result) > 1 else None
            if status_code and status_code >= 200 and status_code < 300:
                increment_usage(user_id)
        else:
            increment_usage(user_id)

        return result
    return decorated_function


def initialize_usage_limits(user_id):
    from app import users_collection

    if users_collection is None:
        return

    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return

    tier = user.get('tier', TIER_DEFAULT)
    session_limit_max, weekly_limit_max = get_tier_limits(tier)

    now = datetime.now()
    session_reset = now + timedelta(hours=5)
    weekly_reset = now + timedelta(days=7)

    usage_limits = {
        'session_limit': {
            'count': 0,
            'reset_at': session_reset,
            'max': session_limit_max if session_limit_max != float('inf') else 999999
        },
        'weekly_limit': {
            'count': 0,
            'reset_at': weekly_reset,
            'max': weekly_limit_max if weekly_limit_max != float('inf') else 999999
        }
    }

    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'usage_limits': usage_limits}}
    )


def get_usage_limits(user_id):
    from app import users_collection

    if users_collection is None:
        return None

    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        return None

    usage_limits = user.get('usage_limits')

    if not usage_limits:
        initialize_usage_limits(user_id)
        return get_usage_limits(user_id)

    tier = user.get('tier', TIER_DEFAULT)
    session_limit_max, weekly_limit_max = get_tier_limits(tier)
    session_limit_max = session_limit_max if session_limit_max != float('inf') else 999999
    weekly_limit_max = weekly_limit_max if weekly_limit_max != float('inf') else 999999

    now = datetime.now()
    needs_reset = False

    session_limit = usage_limits.get('session_limit', {})
    if isinstance(session_limit.get('reset_at'), str):
        session_limit['reset_at'] = datetime.fromisoformat(session_limit['reset_at']).replace(tzinfo=None)

    if session_limit.get('reset_at') and now >= session_limit.get('reset_at'):
        session_limit['count'] = 0
        session_limit['reset_at'] = now + timedelta(hours=5)
        needs_reset = True

    weekly_limit = usage_limits.get('weekly_limit', {})
    if isinstance(weekly_limit.get('reset_at'), str):
        weekly_limit['reset_at'] = datetime.fromisoformat(weekly_limit['reset_at']).replace(tzinfo=None)

    if weekly_limit.get('reset_at') and now >= weekly_limit.get('reset_at'):
        weekly_limit['count'] = 0
        weekly_limit['reset_at'] = now + timedelta(days=7)
        needs_reset = True

    # Update max limits if tier has changed
    if session_limit.get('max') != session_limit_max or weekly_limit.get('max') != weekly_limit_max:
        session_limit['max'] = session_limit_max
        weekly_limit['max'] = weekly_limit_max
        needs_reset = True

    if needs_reset:
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'usage_limits': usage_limits}}
        )

    return usage_limits


def check_usage_limits(user_id):
    limits = get_usage_limits(user_id)

    if not limits:
        return True, None

    session_limit = limits.get('session_limit', {})
    weekly_limit = limits.get('weekly_limit', {})

    session_exceeded = session_limit.get('count', 0) >= session_limit.get('max', 100)
    weekly_exceeded = weekly_limit.get('count', 0) >= weekly_limit.get('max', 500)

    if session_exceeded:
        reset_at = session_limit.get('reset_at')
        if isinstance(reset_at, str):
            reset_at = datetime.fromisoformat(reset_at).replace(tzinfo=None)
        remaining = reset_at - datetime.now()
        minutes = int(remaining.total_seconds() / 60)
        hours = minutes // 60
        minutes = minutes % 60
        return False, f'Session limit reached. Resets in {hours}h {minutes}m'

    if weekly_exceeded:
        reset_at = weekly_limit.get('reset_at')
        if isinstance(reset_at, str):
            reset_at = datetime.fromisoformat(reset_at).replace(tzinfo=None)
        remaining = reset_at - datetime.now()
        days = remaining.days
        minutes = int(remaining.total_seconds() % 86400 / 60)
        hours = minutes // 60
        minutes = minutes % 60
        return False, f'Weekly limit reached. Resets in {days}d {hours}h {minutes}m'

    return True, None


def increment_usage(user_id):
    from app import users_collection

    if users_collection is None:
        return

    limits = get_usage_limits(user_id)

    if limits:
        limits['session_limit']['count'] = limits['session_limit'].get('count', 0) + 1
        limits['weekly_limit']['count'] = limits['weekly_limit'].get('count', 0) + 1

        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'usage_limits': limits}}
        )
