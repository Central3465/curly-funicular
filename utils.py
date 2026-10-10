from flask import jsonify, session, request, g
from functools import wraps
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from bson.errors import InvalidId
import hashlib


# Tier constants
TIER_DEFAULT = 0
TIER_TRUSTED = 1
TIER_PRO = 2
TIER_SUPERUSER = 3

# Base limits for default tier (0)
BASE_SESSION_LIMIT = 50
BASE_WEEKLY_LIMIT = 250

# Tier multipliers
TIER_MULTIPLIERS = {
    TIER_DEFAULT: 1.0,
    TIER_TRUSTED: 1.5,
    TIER_PRO: 0.5,  # pro is now a restricted tier with lower limits
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


def check_account_access(user_id):
    """Returns (message, status) if this account may not make requests, or None if it may."""
    from app import users_collection

    if users_collection is None:
        return 'Service unavailable. Please try again later.', 503

    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
    except InvalidId:
        user = None

    if not user:
        return 'Unauthorized. Please log in.', 401

    if user.get('banned'):
        return 'This account has been banned.', 403

    return None


def check_session_account(user_id):
    """Returns an error response if the logged-in account may not make requests, else None.
    Clears the session when the account is banned or no longer exists."""
    access_error = check_account_access(user_id)
    if not access_error:
        return None

    message, status = access_error
    if status != 503:
        session.clear()
    return jsonify({'error': message}), status


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401

        error_response = check_session_account(user_id)
        if error_response:
            return error_response
        return f(*args, **kwargs)
    return decorated_function


def hash_api_key(api_key):
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()


def get_authenticated_user_id():
    """Returns the logged-in session user_id, or the user_id resolved from an API key, if any."""
    if session.get('user_id'):
        return session.get('user_id')
    return getattr(g, 'api_user_id', None)


def require_auth_or_api_key(f):
    """Like require_auth, but also accepts an X-API-Key header in place of a session login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id'):
            error_response = check_session_account(session.get('user_id'))
            if error_response:
                return error_response
            return f(*args, **kwargs)

        api_key = request.headers.get('X-API-Key')
        if api_key:
            from app import users_collection

            if users_collection is not None:
                user = users_collection.find_one({'api_key_hash': hash_api_key(api_key)})
                if user:
                    if user.get('banned'):
                        return jsonify({'error': 'This account has been banned.'}), 403
                    g.api_user_id = str(user['_id'])
                    return f(*args, **kwargs)

        return jsonify({'error': 'Unauthorized. Please log in or provide a valid API key in the X-API-Key header.'}), 401
    return decorated_function


def is_success_response(result):
    """A plain response counts as success. A (body, status) tuple counts only for a 2xx status."""
    if isinstance(result, tuple) and len(result) >= 2:
        return 200 <= result[1] < 300
    return True


def track_usage(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app import users_collection

        user_id = get_authenticated_user_id()
        if not user_id or users_collection is None:
            return f(*args, **kwargs)

        result = f(*args, **kwargs)

        if is_success_response(result):
            increment_usage(user_id)

        return result
    return decorated_function


def track_quests(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app import users_collection

        user_id = get_authenticated_user_id()
        if not user_id or users_collection is None:
            return f(*args, **kwargs)

        result = f(*args, **kwargs)

        if is_success_response(result):
            users_collection.update_one({'_id': ObjectId(user_id)}, {'$inc': {'completed_quests': 1}})

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

    session_exceeded = session_limit.get('count', 0) >= session_limit.get('max', 50)
    weekly_exceeded = weekly_limit.get('count', 0) >= weekly_limit.get('max', 250)

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

    # Make sure usage_limits exist before incrementing them
    if not get_usage_limits(user_id):
        return

    # $inc updates the counts atomically, so concurrent requests can't overwrite each other
    users_collection.update_one(
        {'_id': ObjectId(user_id)},
        {'$inc': {'usage_limits.session_limit.count': 1, 'usage_limits.weekly_limit.count': 1}}
    )
