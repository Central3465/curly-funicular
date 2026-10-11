from flask import jsonify, session
from api import quest_bp
from utils import require_auth, get_usage_limits, TIER_DEFAULT, TIER_TRUSTED, TIER_SUPERUSER
from datetime import datetime
from bson.objectid import ObjectId

# (rank name, XP required, tier granted), lowest to highest
RANKS = [
    ('Trusted', 500, TIER_TRUSTED),
    ('Superuser', 1000, TIER_SUPERUSER),
]

@quest_bp.route('/api/get-quests', methods=['GET'])
@require_auth
def get_quests():
    # quests are now levels, the logic for quests was too complicated
    # furthermore, track_quests() now adds 1 to the user's completed_quests variable
    quests = {
        'Trusted':'500',
        'Superuser':'1000',
    }

    user_id = session.get('user_id')

    from app import users_collection
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    completed_quests = user.get('completed_quests', 0)

    return jsonify({'quests': quests, 'completed_quests': completed_quests})

@quest_bp.route('/api/check-rankup', methods=['GET'])
@require_auth
def check_rankup():
    user_id = session.get('user_id')

    from app import users_collection
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'error': 'User not found'}), 404

    completed_quests = user.get('completed_quests', 0)
    
    if completed_quests == 0:
        return jsonify({'rankup': False, 'message': 'No quests completed yet.'})

    current_tier = user.get('tier', TIER_DEFAULT)

    # the next rank is the lowest one above the user's current tier
    next_rank = next((rank for rank in RANKS if rank[2] > current_tier), None)

    if next_rank is None:
        return jsonify({'rankup': False, 'message': 'You are already at the highest rank.'})

    name, xp_required, _ = next_rank

    if completed_quests >= xp_required:
        return jsonify({'rankup': True, 'new_rank': name, 'message': f'You have {completed_quests} XP and are eligible to rank up to {name}.'})

    return jsonify({'rankup': False, 'message': f'You have {completed_quests} XP. You need {xp_required - completed_quests} more XP to rank up to {name}.'})
