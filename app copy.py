from flask import Flask, redirect, url_for, session, request, render_template
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv
import os
import xml.etree.ElementTree as ET
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash




service_account_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')

if not service_account_path:
    raise Exception('Set the GOOGLE_APPLICATION_CREDENTIALS environment variable.')

# Initialize Firebase Admin SDK
cred = credentials.Certificate(service_account_path)
firebase_admin.initialize_app(cred)

# Initialize Firestore DB
db = firestore.client()

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')

# OAuth endpoints given in the Hattrick API documentation
REQUEST_TOKEN_URL = 'https://chpp.hattrick.org/oauth/request_token.ashx'
AUTHORIZATION_URL = 'https://chpp.hattrick.org/oauth/authorize.aspx'
ACCESS_TOKEN_URL = 'https://chpp.hattrick.org/oauth/access_token.ashx'

# Get your application's key and secret from environment variables
CONSUMER_KEY = os.environ.get('HATTRICK_CONSUMER_KEY')
CONSUMER_SECRET = os.environ.get('HATTRICK_CONSUMER_SECRET')

@app.route('/')
def index():
    return render_template('login.html')

# Other routes will be added in the next steps
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Basic validation
        if not email or not password or not confirm_password:
            return render_template('error.html', message='Please fill out all fields.')

        if password != confirm_password:
            return render_template('error.html', message='Passwords do not match.')

        # Check if user already exists
        users_ref = db.collection('users')
        existing_user = users_ref.where('email', '==', email).get()
        if existing_user:
            return render_template('error.html', message='Email is already registered.')

        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        # Create user document
        user_data = {
            'email': email,
            'password': hashed_password,
            'hattrick_connected': False
        }
        # Generate a unique user ID (you can also use email as the document ID)
        user_id = email  # or generate a UUID

        users_ref.document(user_id).set(user_data)

        # Log the user in by setting session variables
        session['user_id'] = user_id
        session['email'] = email

        return redirect(url_for('dashboard'))
    else:
        return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch user from database
        users_ref = db.collection('users')
        user_doc = users_ref.document(email).get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            stored_password = user_data.get('password')

            # Verify password
            if check_password_hash(stored_password, password):
                # Set session variables
                session['user_id'] = email
                session['email'] = email
                return redirect(url_for('dashboard'))
            else:
                return render_template('error.html', message='Invalid password.')
        else:
            return render_template('error.html', message='Email not registered.')
    else:
        return render_template('login.html')

@app.route('/hattrick_callback')
def hattrick_callback():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    resource_owner_key = session.get('resource_owner_key')
    resource_owner_secret = session.get('resource_owner_secret')
    oauth_verifier = request.args.get('oauth_verifier')

    if not resource_owner_key or not resource_owner_secret:
        return render_template('error.html', message='Missing resource owner key and secret. Please try connecting again.')

    oauth = OAuth1Session(
        CONSUMER_KEY,
        client_secret=CONSUMER_SECRET,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=oauth_verifier
    )

    try:
        oauth_tokens = oauth.fetch_access_token(ACCESS_TOKEN_URL)
    except Exception as e:
        return render_template('error.html', message=f'Error fetching access token: {e}')

    access_token = oauth_tokens.get('oauth_token')
    access_token_secret = oauth_tokens.get('oauth_token_secret')

    # Fetch user data from Hattrick API
    oauth = OAuth1Session(
        CONSUMER_KEY,
        client_secret=CONSUMER_SECRET,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret
    )
    response = oauth.get('https://chpp.hattrick.org/chppxml.ashx?file=managercompendium')

    if response.status_code != 200:
        return render_template('error.html', message=f'Error fetching user data from Hattrick: {response.status_code}')

    # Parse the XML response
    root = ET.fromstring(response.content)
    manager = root.find('.//Manager')

    if manager is None:
        return render_template('error.html', message='Manager element not found in the XML response.')

    manager_name = manager.find('ManagerName').text
    hattrick_user_id = manager.find('UserID').text

    # Update user document in Firestore
    user_id = session['user_id']
    users_ref = db.collection('users')
    user_ref = users_ref.document(user_id)

    user_ref.update({
        'hattrick_connected': True,
        'manager_name': manager_name,
        'hattrick_user_id': hattrick_user_id,
        'access_token': access_token,
        'access_token_secret': access_token_secret
    })

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    users_ref = db.collection('users')
    user_doc = users_ref.document(user_id).get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        hattrick_connected = user_data.get('hattrick_connected', False)
        manager_name = user_data.get('manager_name', '')

        return render_template('dashboard.html', hattrick_connected=hattrick_connected, manager_name=manager_name)
    else:
        return render_template('error.html', message='User not found.')

@app.route('/connect_hattrick')
def connect_hattrick():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Begin OAuth flow as before
    oauth = OAuth1Session(
        CONSUMER_KEY,
        client_secret=CONSUMER_SECRET,
        callback_uri=url_for('hattrick_callback', _external=True)
    )

    try:
        fetch_response = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    except Exception as e:
        return render_template('error.html', message=f'Error fetching request token: {e}')

    # Store the request token in the session
    session['resource_owner_key'] = fetch_response.get('oauth_token')
    session['resource_owner_secret'] = fetch_response.get('oauth_token_secret')

    # Redirect the user to Hattrick for authorization
    authorization_url = oauth.authorization_url(AUTHORIZATION_URL)
    return redirect(authorization_url)

@app.route('/profile')
def profile():

    hattrick_user_id = session.get('hattrick_user_id')

    if not hattrick_user_id:
        return redirect(url_for('index'))

    user_ref = db.collection('users').document(hattrick_user_id)
    user_doc = user_ref.get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        return render_template('profile.html', user_data=user_data)
    else:
        return render_template('error.html', message='User not found.')

@app.route('/add_friend', methods=['POST'])
def add_friend_route():
    # Get the current user ID and the friend ID from the form
    current_user_id = session.get('hattrick_user_id')
    friend_id = request.form.get('friend_id')

    if not current_user_id or not friend_id:
        return render_template('error.html', message='Invalid user IDs.')

    add_friend(current_user_id, friend_id)
    return redirect(url_for('dashboard'))

@app.route('/delete_friend', methods=['POST'])
def delete_friend_route():
    # Get the current user ID and the friend ID from the form
    current_user_id = session.get('hattrick_user_id')
    friend_id = request.form.get('friend_id')

    if not current_user_id or not friend_id:
        return render_template('error.html', message='Invalid user IDs.')

    add_friend(current_user_id, friend_id)
    return redirect(url_for('dashboard'))

@app.route('/accept_friend', methods=['POST'])
def accept_friend_route():
    current_user_id = session.get('hattrick_user_id')
    friend_id = request.form.get('friend_id')

    if not current_user_id or not friend_id:
        return render_template('error.html', message='Invalid user IDs.')

    accept_friend(current_user_id, friend_id)
    return redirect(url_for('dashboard'))


@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message='An unexpected error occurred.'), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', message='Page not found.'), 404

if __name__ == '__main__':
    app.run(debug=True)