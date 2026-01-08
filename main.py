import os
import secrets
import requests
from flask import Flask, redirect, url_for, session, render_template, request
from urllib.parse import urlencode
import base64
import hashlib
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

CLIENT_ID = os.environ.get('TWITTER_CLIENT_ID')
CLIENT_SECRET = os.environ.get('TWITTER_CLIENT_SECRET')
REDIRECT_URI = os.environ.get('REDIRECT_URI', 'http://localhost:5000/callback')

AUTHORIZATION_URL = 'https://twitter.com/i/oauth2/authorize'
TOKEN_URL = 'https://api.twitter.com/2/oauth2/token'


def generate_code_verifier():
    return secrets.token_urlsafe(32)


def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


@app.route('/health')
def health():
    return 'OK', 200


@app.route('/')
def home():
    if 'access_token' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/login')
def login():
    if not CLIENT_ID:
        return "Error: TWITTER_CLIENT_ID not set", 500

    code_verifier = generate_code_verifier()
    session['code_verifier'] = code_verifier
    code_challenge = generate_code_challenge(code_verifier)

    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state

    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'tweet.read users.read offline.access',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    auth_url = f"{AUTHORIZATION_URL}?{urlencode(params)}"
    return redirect(auth_url)


@app.route('/callback')
def callback():
    error = request.args.get('error')
    if error:
        return f"Error: {error}", 400

    code = request.args.get('code')
    state = request.args.get('state')

    if state != session.get('oauth_state'):
        return "State mismatch error", 400

    code_verifier = session.get('code_verifier')

    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier
    }

    auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    headers = {
        'Authorization': f'Basic {auth_header}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(TOKEN_URL, data=token_data, headers=headers)

    if response.status_code != 200:
        return f"Token error: {response.text}", 400

    tokens = response.json()
    session['access_token'] = tokens['access_token']

    session.pop('oauth_state', None)
    session.pop('code_verifier', None)

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    if 'access_token' not in session:
        return redirect(url_for('home'))

    access_token = session['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}

    # Get user info
    user_response = requests.get(
        'https://api.twitter.com/2/users/me',
        headers=headers
    )

    if user_response.status_code != 200:
        session.clear()
        return redirect(url_for('home'))

    user_data = user_response.json().get('data', {})
    user_id = user_data.get('id')
    username = user_data.get('username')

    # Get last 3 tweets
    tweets_response = requests.get(
        f'https://api.twitter.com/2/users/{user_id}/tweets',
        headers=headers,
        params={
            'max_results': 5,
            'tweet.fields': 'created_at,public_metrics'
        }
    )

    tweets = []
    if tweets_response.status_code == 200:
        tweets = tweets_response.json().get('data', [])
    else :
        # log response error and code
        print(f"Error fetching tweets: {tweets_response.status_code} - {tweets_response.text}")

    return render_template('dashboard.html', username=username, tweets=tweets)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
