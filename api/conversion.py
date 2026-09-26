from flask import jsonify, request, session
from cipher import convert_base, ascii_to_base, base_to_ascii
from api import conversion_bp
from utils import require_auth, track_usage, check_usage_limits


@conversion_bp.route('/api/convert-base', methods=['POST'])
@require_auth
@track_usage
def convert_base_endpoint():
    can_proceed, error_msg = check_usage_limits(session.get('user_id'))
    if not can_proceed:
        return jsonify({'error': error_msg}), 429

    data = request.get_json()
    number = data.get('number', '').strip()
    from_base = data.get('from_base')
    to_base = data.get('to_base')

    if not number:
        return jsonify({'error': 'Number cannot be empty'}), 400

    try:
        from_base = int(from_base)
        to_base = int(to_base)

        if not (2 <= from_base <= 36) or not (2 <= to_base <= 36):
            return jsonify({'error': 'Base must be between 2 and 36'}), 400

        result = convert_base(number, from_base, to_base)
        return jsonify({'result': result, 'success': True})
    except ValueError as e:
        return jsonify({'error': f'Invalid number for base {from_base}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@conversion_bp.route('/api/ascii-to-base', methods=['POST'])
@require_auth
@track_usage
def ascii_to_base_endpoint():
    can_proceed, error_msg = check_usage_limits(session.get('user_id'))
    if not can_proceed:
        return jsonify({'error': error_msg}), 429

    data = request.get_json()
    text = data.get('text', '')
    base = data.get('base')

    if not text:
        return jsonify({'error': 'Text cannot be empty'}), 400

    try:
        base = int(base)

        if not (2 <= base <= 36):
            return jsonify({'error': 'Base must be between 2 and 36'}), 400

        result = ascii_to_base(text, base)
        return jsonify({'result': result, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@conversion_bp.route('/api/base-to-ascii', methods=['POST'])
@require_auth
@track_usage
def base_to_ascii_endpoint():
    can_proceed, error_msg = check_usage_limits(session.get('user_id'))
    if not can_proceed:
        return jsonify({'error': error_msg}), 429

    data = request.get_json()
    numbers = data.get('numbers', '').strip()
    base = data.get('base')

    if not numbers:
        return jsonify({'error': 'Numbers cannot be empty'}), 400

    try:
        base = int(base)

        if not (2 <= base <= 36):
            return jsonify({'error': 'Base must be between 2 and 36'}), 400

        result = base_to_ascii(numbers, base)
        return jsonify({'result': result, 'success': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
