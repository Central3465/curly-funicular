from flask import jsonify, request, session
from cipher import decode_message, validate_cipher, encode_message, create_random_cipher
from api import cipher_bp
from utils import require_auth, track_usage, check_usage_limits


@cipher_bp.route('/api/validate-cipher', methods=['POST'])
@require_auth
@track_usage
def validate_cipher_endpoint():
    can_proceed, error_msg = check_usage_limits(session.get('user_id'))
    if not can_proceed:
        return jsonify({'error': error_msg}), 429

    data = request.get_json()
    cipher_input = data.get('cipher', '')

    is_valid, result = validate_cipher(cipher_input)

    if is_valid:
        return jsonify({'valid': True, 'cipher': result})
    else:
        return jsonify({'valid': False, 'error': result})


@cipher_bp.route('/api/decode', methods=['POST'])
@require_auth
@track_usage
def decode_endpoint():
    can_proceed, error_msg = check_usage_limits(session.get('user_id'))
    if not can_proceed:
        return jsonify({'error': error_msg}), 429

    data = request.get_json()

    cipher_input = data.get('cipher', '')
    encrypted_message = data.get('message', '')
    key = data.get('key', '')

    if not key:
        return jsonify({'error': 'Key cannot be empty'}), 400

    is_valid, cipher_or_error = validate_cipher(cipher_input)
    if not is_valid:
        return jsonify({'error': cipher_or_error}), 400

    try:
        decoded = decode_message(encrypted_message, cipher_or_error, key)
        return jsonify({'decoded': decoded})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cipher_bp.route('/api/generate-cipher', methods=['POST'])
@require_auth
@track_usage
def generate_cipher_endpoint():
    can_proceed, error_msg = check_usage_limits(session.get('user_id'))
    if not can_proceed:
        return jsonify({'error': error_msg}), 429

    try:
        cipher = create_random_cipher()
        return jsonify({'cipher': cipher, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cipher_bp.route('/api/encode', methods=['POST'])
@require_auth
@track_usage
def encode_endpoint():
    can_proceed, error_msg = check_usage_limits(session.get('user_id'))
    if not can_proceed:
        return jsonify({'error': error_msg}), 429

    data = request.get_json()

    cipher_input = data.get('cipher', '')
    message = data.get('message', '')
    key = data.get('key', '')

    if not key:
        return jsonify({'error': 'Key cannot be empty'}), 400

    is_valid, cipher_or_error = validate_cipher(cipher_input)
    if not is_valid:
        return jsonify({'error': cipher_or_error}), 400

    try:
        encrypted = encode_message(message, cipher_or_error, key)
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
