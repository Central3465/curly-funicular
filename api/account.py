from flask import jsonify, request
from datetime import datetime
import requests
import os
from api import account_bp


@account_bp.route('/api/request-account', methods=['POST'])
def request_account():
    from app import get_client_ip, validate_email, is_ip_banned

    data = request.get_json()
    full_name = data.get('fullName', '').strip()
    email = data.get('email', '').strip().lower()
    description = data.get('description', '').strip()
    client_ip = get_client_ip()

    if not full_name or not email or not description:
        return jsonify({'error': 'All fields are required'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address'}), 400

    if len(description) < 10:
        return jsonify({'error': 'Description must be at least 10 characters'}), 400

    discord_webhook_url = os.getenv('DISCORD_WEBHOOK_URL')
    if discord_webhook_url:
        embed = {
            'title': '🔐 New Account Request',
            'description': description,
            'color': 4886754,
            'fields': [
                {'name': 'Full Name', 'value': full_name, 'inline': True},
                {'name': 'Email', 'value': email, 'inline': True},
                {'name': 'IP Address', 'value': client_ip, 'inline': True},
                {'name': 'Timestamp', 'value': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'), 'inline': True}
            ]
        }

        payload = {'embeds': [embed]}

        try:
            response = requests.post(discord_webhook_url, json=payload, timeout=5)
            if response.status_code not in [200, 204]:
                print(f"Discord webhook failed with status {response.status_code}: {response.text}")
        except Exception as e:
            print(f"Error sending Discord webhook: {e}")

    return jsonify({'success': True, 'message': 'Account request submitted successfully'}), 200


@account_bp.route('/api/check-ip-ban', methods=['GET'])
def check_ip_ban():
    from app import get_client_ip, is_ip_banned

    client_ip = get_client_ip()
    is_banned, remaining = is_ip_banned(client_ip)

    if is_banned:
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        return jsonify({
            'banned': True,
            'remaining_time': f"{hours}h {minutes}m",
            'message': f'This IP address has been banned. Please try again in {hours}h {minutes}m.'
        })

    return jsonify({'banned': False})
