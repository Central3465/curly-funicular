from flask import Flask, render_template, request, jsonify
from cipher import decode_message, validate_cipher, encode_message, create_random_cipher

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/validate-cipher', methods=['POST'])
def validate_cipher_endpoint():
    data = request.get_json()
    cipher_input = data.get('cipher', '')

    is_valid, result = validate_cipher(cipher_input)

    if is_valid:
        return jsonify({'valid': True, 'cipher': result})
    else:
        return jsonify({'valid': False, 'error': result})


@app.route('/api/decode', methods=['POST'])
def decode_endpoint():
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


@app.route('/api/generate-cipher', methods=['POST'])
def generate_cipher_endpoint():
    try:
        cipher = create_random_cipher()
        return jsonify({'cipher': cipher, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/encode', methods=['POST'])
def encode_endpoint():
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


if __name__ == '__main__':
    app.run(debug=True)