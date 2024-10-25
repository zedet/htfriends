from flask import Flask, render_template, redirect, url_for, request, session, flash
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import os
import uuid
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import timedelta
import xml.etree.ElementTree as ET

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')


RESET_TOKEN_EXPIRATION = int(os.environ.get('RESET_TOKEN_EXPIRATION', 3600))

# OAuth endpoints
REQUEST_TOKEN_URL = 'https://chpp.hattrick.org/oauth/request_token.ashx'
AUTHORIZATION_URL = 'https://chpp.hattrick.org/oauth/authorize.aspx'
ACCESS_TOKEN_URL = 'https://chpp.hattrick.org/oauth/access_token.ashx'

# Hattrick API credentials
CONSUMER_KEY = os.environ.get('HATTRICK_CONSUMER_KEY')
CONSUMER_SECRET = os.environ.get('HATTRICK_CONSUMER_SECRET')

# Initialize Firebase Admin SDK
cred = credentials.Certificate(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))
firebase_admin.initialize_app(cred)
db = firestore.client()

# Configure Flask-Mail
app.config.update(
    MAIL_SERVER=os.environ.get('MAIL_SERVER'),
    MAIL_PORT=int(os.environ.get('MAIL_PORT')),
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS') == 'True',
    MAIL_USE_SSL=os.environ.get('MAIL_USE_SSL') == 'True',
    MAIL_DEFAULT_SENDER=('Your App Name', 'no-reply@yourapp.com')
)
mail = Mail(app)

# Helper function to send verification email
def send_verification_email(email, verification_code):
    msg = Message('Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
    link = url_for('verify_email', code=verification_code, _external=True)
    msg.body = f'Please click the following link to verify your email: {link}'
    return
    mail.send(msg)

# Route for the initial page
@app.route('/')
def index():
    return render_template('index.html')

# User registration route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Basic validation
        if not email or not password or not confirm_password:
            flash('Please fill out all fields.')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        # Check if user already exists
        users_ref = db.collection('users')
        existing_user = users_ref.document(email).get()
        if existing_user.exists:
            flash('Email is already registered.')
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Generate verification code
        verification_code = str(uuid.uuid4())

        # Create user document
        user_data = {
            'email': email,
            'password': hashed_password,
            'is_verified': True,
            'verification_code': verification_code,
            'hattrick_connected': False
        }

        

        # Send verification email
        send_verification_email(email, verification_code)
        flash('A verification email has been sent to your email address.')
        
        users_ref.document(email).set(user_data)
        
        return redirect(url_for('login'))
    else:
        return render_template('signup.html')

# Email verification route
@app.route('/verify_email/<code>')
def verify_email(code):
    users_ref = db.collection('users')
    users = users_ref.where('verification_code', '==', code).get()

    if not users:
        flash('Invalid or expired verification link.')
        return redirect(url_for('login'))

    user_ref = users[0].reference
    user_ref.update({
        'is_verified': True,
        'verification_code': None
    })

    # Render a template instead of redirecting immediately
    return render_template('email_verified.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch user from database
        users_ref = db.collection('users')
        user_doc = users_ref.document(email).get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            if not user_data.get('is_verified'):
                flash('Please verify your email before logging in.')
                return redirect(url_for('login'))

            stored_password = user_data.get('password')

            # Verify password
            if check_password_hash(stored_password, password):
                # Set session variables
                session['user_id'] = email
                session['email'] = email
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password.')
                return redirect(url_for('login'))
        else:
            flash('Email not registered.')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email exists in the database
        users_ref = db.collection('users')
        user_doc = users_ref.document(email).get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            if not user_data.get('is_verified'):
                flash('Email is not verified. Please verify your email first.')
                return redirect(url_for('login'))

            # Generate a password reset token
            reset_token = str(uuid.uuid4())

            # Store the token and its expiration time in the user's document
            user_ref = users_ref.document(email)
            # Set token expiration time (e.g., 1 hour from now)
            expiration_time = datetime.utcnow() + timedelta(hours=1)
            user_ref.update({
                'reset_token': reset_token,
                'reset_token_expiration': expiration_time
            })

            # Send password reset email
            send_password_reset_email(email, reset_token)
        # Always flash the same message
        flash('If an account with that email exists, a password reset link has been sent.')
        return redirect(url_for('login'))
    else:
        return render_template('forgot_password.html')

from datetime import datetime, timedelta

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    users_ref = db.collection('users')
    # Find the user with the given reset token
    users = users_ref.where('reset_token', '==', token).get()

    if not users:
        flash('Invalid or expired password reset link.')
        return redirect(url_for('login'))

    user_ref = users[0].reference
    user_data = users[0].to_dict()

    # Check if the token has expired (e.g., valid for 1 hour)
    token_expiration_time = user_data.get('reset_token_expiration')
    if token_expiration_time and datetime.utcnow() > token_expiration_time:
        flash('Password reset link has expired.')
        return redirect(url_for('forgot_password'))    

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            flash('Please fill out all fields.')
            return redirect(url_for('reset_password', token=token))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', token=token))

        # Hash the new password
        hashed_password = generate_password_hash(password)

        # Update the user's password and remove the reset token
        user_ref.update({
            'password': hashed_password,
            'reset_token': firestore.DELETE_FIELD,
            'reset_token_expiration': firestore.DELETE_FIELD
        })

        flash('Your password has been reset successfully. You can now log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    users_ref = db.collection('users')
    user_doc = users_ref.document(user_id).get()

    if not user_doc.exists:
        flash('User not found.')
        return redirect(url_for('login'))

    user_data = user_doc.to_dict()
    hattrick_connected = user_data.get('hattrick_connected', False)
    manager_name = user_data.get('manager_name', '')
    access_token = user_data.get('access_token')
    access_token_secret = user_data.get('access_token_secret')

    teams = []
    supporter_tier = ''

    if hattrick_connected and access_token and access_token_secret:
        # Fetch latest data from Hattrick API
        oauth = OAuth1Session(
            CONSUMER_KEY,
            client_secret=CONSUMER_SECRET,
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret
        )

        # Get manager compendium to retrieve SupporterTier and Teams
        response = oauth.get('https://chpp.hattrick.org/chppxml.ashx?file=managercompendium')
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            manager = root.find('.//Manager')

            if manager is not None:
                manager_name_elem = manager.find('Loginname')
                manager_name = manager_name_elem.text if manager_name_elem is not None else manager_name

                # Extract SupporterTier
                supporter_tier_elem = manager.find('SupporterTier')
                supporter_tier = supporter_tier_elem.text if supporter_tier_elem is not None else ''

                # Extract Teams
                teams_elem = manager.find('Teams')
                if teams_elem is not None:
                    teams = []
                    for team in teams_elem.findall('Team'):
                        team_id = team.find('TeamId').text
                        team_name = team.find('TeamName').text
                        teams.append({'team_id': team_id, 'team_name': team_name})
            else:
                flash('Manager information not found in Hattrick data.')
        else:
            if response.status_code == 401:
                flash('Your Hattrick session has expired. Please reconnect your account.')
                return redirect(url_for('connect_hattrick'))
            elif response.status_code != 200:
                flash('Error fetching data from Hattrick.')
                return redirect(url_for('dashboard'))
                

        # Optional: Update user's manager name in the database
        users_ref.document(user_id).update({
            'manager_name': manager_name
        })

    # Fetch friends and friend requests
    friends = []
    friends_collection = users_ref.document(user_id).collection('friends')
    friends_docs = friends_collection.where('status', '==', 'accepted').stream()
    for doc in friends_docs:
        friend_email = doc.id
        friends.append(friend_email)

    friend_requests = []
    friend_requests_collection = users_ref.document(user_id).collection('friend_requests')
    friend_requests_docs = friend_requests_collection.stream()
    for doc in friend_requests_docs:
        requester_email = doc.id
        friend_requests.append(requester_email)

    # Fetch groups
    groups = []
    groups_collection = users_ref.document(user_id).collection('groups')
    groups_docs = groups_collection.stream()
    for doc in groups_docs:
        group_data = doc.to_dict()
        groups.append(group_data)

    return render_template(
        'dashboard.html',
        hattrick_connected=hattrick_connected,
        manager_name=manager_name,
        teams=teams,
        supporter_tier=supporter_tier,
        friends=friends,
        friend_requests=friend_requests,
        groups=groups
    )

# Route to connect Hattrick account
@app.route('/connect_hattrick')
def connect_hattrick():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Begin OAuth flow
    oauth = OAuth1Session(
        CONSUMER_KEY,
        client_secret=CONSUMER_SECRET,
        callback_uri=url_for('hattrick_callback', _external=True)
    )

    try:
        fetch_response = oauth.fetch_request_token(REQUEST_TOKEN_URL)
    except Exception as e:
        flash(f'Error fetching request token: {e}')
        return redirect(url_for('dashboard'))

    # Store the request token in the session
    session['resource_owner_key'] = fetch_response.get('oauth_token')
    session['resource_owner_secret'] = fetch_response.get('oauth_token_secret')

    # Redirect the user to Hattrick for authorization
    authorization_url = oauth.authorization_url(AUTHORIZATION_URL)
    return redirect(authorization_url)
@app.route('/add_friend', methods=['POST'])
def add_friend():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    friend_email = request.form.get('friend_email')

    if not friend_email:
        flash('Please enter an email address.')
        return redirect(url_for('dashboard'))

    users_ref = db.collection('users')
    friend_doc = users_ref.document(friend_email).get()

    if not friend_doc.exists:
        flash('User not found.')
        return redirect(url_for('dashboard'))

    # Check if already friends
    current_user_ref = users_ref.document(current_user_id)
    existing_friendship = current_user_ref.collection('friends').document(friend_email).get()
    if existing_friendship.exists:
        friendship_status = existing_friendship.to_dict().get('status')
        if friendship_status == 'accepted':
            flash('You are already friends with this user.')
        elif friendship_status == 'pending':
            flash('Friend request already sent.')
        return redirect(url_for('dashboard'))

    # Add friend request
    current_user_ref.collection('friends').document(friend_email).set({
        'status': 'pending',
        'friend_email': friend_email
    })

    # Add to friend's friend_requests subcollection
    friend_ref = users_ref.document(friend_email)
    friend_ref.collection('friend_requests').document(current_user_id).set({
        'status': 'pending',
        'friend_email': current_user_id
    })

    flash('Friend request sent.')
    return redirect(url_for('dashboard'))

@app.route('/accept_friend', methods=['POST'])
def accept_friend():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    friend_email = request.form.get('friend_email')

    if not friend_email:
        flash('Invalid friend email.')
        return redirect(url_for('dashboard'))

    users_ref = db.collection('users')
    current_user_ref = users_ref.document(current_user_id)
    friend_ref = users_ref.document(friend_email)

    # Update friend status to 'accepted' for both users
    current_user_ref.collection('friends').document(friend_email).set({
        'status': 'accepted',
        'friend_email': friend_email
    })

    friend_ref.collection('friends').document(current_user_id).set({
        'status': 'accepted',
        'friend_email': current_user_id
    })

    # Remove the friend request
    current_user_ref.collection('friend_requests').document(friend_email).delete()
    friend_ref.collection('friend_requests').document(current_user_id).delete()

    flash('Friend request accepted.')
    return redirect(url_for('dashboard'))

@app.route('/remove_friend', methods=['POST'])
def remove_friend():    
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    friend_email = request.form.get('friend_email')

    if not friend_email:
        flash('Invalid friend email.')
        return redirect(url_for('dashboard'))

    users_ref = db.collection('users')
    current_user_ref = users_ref.document(current_user_id)
    friend_ref = users_ref.document(friend_email)

    # Remove the friendship
    current_user_ref.collection('friends').document(friend_email).delete()
    friend_ref.collection('friends').document(current_user_id).delete()

    flash('Friend removed.')
    return redirect(url_for('dashboard'))

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    group_name = request.form.get('group_name')
    member_emails = request.form.getlist('member_emails')  # This gets a list of selected friends

    if not group_name:
        flash('Group name is required.')
        return redirect(url_for('dashboard'))

    # Include the creator's email in the group members
    members = member_emails + [user_id]

    # Create a unique group ID
    group_id = str(uuid.uuid4())

    # Prepare group data
    group_data = {
        'group_name': group_name,
        'members': members
    }

    # Store the group data in Firestore under the user's 'groups' subcollection
    users_ref = db.collection('users')
    user_ref = users_ref.document(user_id)
    user_ref.collection('groups').document(group_id).set(group_data)

    flash('Group created successfully.')
    return redirect(url_for('dashboard'))

# OAuth callback route
@app.route('/hattrick_callback')
def hattrick_callback():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    resource_owner_key = session.get('resource_owner_key')
    resource_owner_secret = session.get('resource_owner_secret')
    oauth_verifier = request.args.get('oauth_verifier')

    if not resource_owner_key or not resource_owner_secret:
        flash('Missing resource owner key and secret. Please try connecting again.')
        return redirect(url_for('dashboard'))

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
        flash(f'Error fetching access token: {e}')
        return redirect(url_for('dashboard'))

    access_token = oauth_tokens.get('oauth_token')
    access_token_secret = oauth_tokens.get('oauth_token_secret')

    # Fetch user data from Hattrick API
    oauth = OAuth1Session(
        CONSUMER_KEY,
        client_secret=CONSUMER_SECRET,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret
    )   

    # Update user document in Firestore
    user_id = session['user_id']
    users_ref = db.collection('users')
    user_ref = users_ref.document(user_id)

    user_ref.update({
        'hattrick_connected': True,
        'access_token': access_token,
        'access_token_secret': access_token_secret
    })

    flash('Hattrick account connected successfully.')
    return redirect(url_for('dashboard'))

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Error handling
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', message='Page not found.'), 404
from datetime import datetime, timedelta

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message='An unexpected error occurred.'), 500

######################## functions ########################
def send_password_reset_email(email, reset_token):
    msg = Message('Reset Your Password', sender=app.config['MAIL_USERNAME'], recipients=[email])
    link = url_for('reset_password', token=reset_token, _external=True)
    msg.body = f'Please click the following link to reset your password: {link}\n\nIf you did not request a password reset, please ignore this email.'
    mail.send(msg)

if __name__ == '__main__':
    app.run(debug=True)
