from flask import jsonify
from flask_wtf.csrf import generate_csrf
from api import csrf_bp


@csrf_bp.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})


get_csrf_token.csrf_exempt = True
