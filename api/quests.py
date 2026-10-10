from flask import jsonify, session
from api import quest_bp
from utils import require_auth, get_usage_limits
from datetime import datetime
from bson.objectid import ObjectId

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
    
    ranks = {
        "Trusted": 500,
        "Superuser": 1000
    }

    for a, b in ranks.items():
        if completed_quests >= b and user.get('tier') < 1:
            return jsonify({'rankup': True, 'new_rank': {user.get('tier') + 1}, 'message': f'You have the required amount of XP {completed_quests} and is eligible to rank up to {a}.'})

    return jsonify({'rankup': False, 'message': f'You have {completed_quests} XP. You need more XP to rank up.'})        