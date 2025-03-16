from flask import Flask, render_template, request, session, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
import hashlib
import secrets
import socket
from database import Database
from datetime import datetime
import logging
import os
from dotenv import load_dotenv
import bcrypt
import jwt
from functools import wraps
import json

# Load environment variables
load_dotenv()

def get_local_ip():
    """Get the local IP address of the machine"""
    try:
        # Create a socket connection to an external server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually connect to 8.8.8.8 but helps get the local IP
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"  # Return localhost if can't determine IP

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
socketio = SocketIO(app)
db = Database()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize OAuth
oauth = OAuth(app)

# Configure Google OAuth
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Configure GitHub OAuth
oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data['email']

@login_manager.user_loader
def load_user(user_id):
    user_data = db.get_user_by_id(user_id)
    if user_data:
        return User(user_data)
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Missing email or password'})

    user = db.get_user_by_email(email)
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify({'success': False, 'message': 'Invalid email or password'})

    session['user_id'] = user['id']
    db.update_user_login(user['id'])
    
    return jsonify({'success': True})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'success': False, 'message': 'Missing required fields'})

    # Check if email already exists
    if db.get_user_by_email(email):
        return jsonify({'success': False, 'message': 'Email already registered'})

    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Create user
    user_id = db.create_user(
        username=username,
        email=email,
        password_hash=password_hash.decode()
    )

    if not user_id:
        return jsonify({'success': False, 'message': 'Error creating user'})

    return jsonify({'success': True})

@app.route('/login/google')
def google_login():
    # Get device info from query parameters
    device_id = request.args.get('device_id')
    device_name = request.args.get('device_name')
    
    if not device_id or not device_name:
        return jsonify({
            'success': False,
            'message': 'Missing device_id or device_name'
        }), 400
    
    # Store device info in state parameter
    state = {
        'device_id': device_id,
        'device_name': device_name
    }
    
    redirect_uri = url_for('google_authorized', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, state=json.dumps(state))

@app.route('/login/google/authorized')
def google_authorized():
    try:
        token = oauth.google.authorize_access_token()
        
        # Get device info from state
        state = json.loads(token.get('state', '{}'))
        device_id = state.get('device_id')
        device_name = state.get('device_name')
        
        if not device_id or not device_name:
            return jsonify({
                'success': False,
                'message': 'Device information not found in state'
            }), 400
            
        resp = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        
        # Check if user exists
        user = db.get_user_by_oauth('google', user_info['sub'])
        
        if not user:
            # Create new user with device info
            user_id = db.create_user(
                username=user_info['name'],
                email=user_info['email'],
                oauth_provider='google',
                oauth_id=user_info['sub'],
                profile_picture=user_info.get('picture'),
                device_id=device_id,
                device_name=device_name
            )
        else:
            user_id = user['id']
            # Update user's device info and last login
            db.update_user_device(user_id, device_id, device_name)
            db.update_user_login(user_id)

        session['user_id'] = user_id
        return redirect(url_for('index'))
        
    except Exception as e:
        logging.error(f"Google OAuth error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Authentication failed',
            'error': str(e)
        }), 500

@app.route('/login/github')
def github_login():
    # Get device info from query parameters
    device_id = request.args.get('device_id')
    device_name = request.args.get('device_name')
    
    if not device_id or not device_name:
        return jsonify({
            'success': False,
            'message': 'Missing device_id or device_name'
        }), 400
    
    # Store device info in session for later use
    session['device_id'] = device_id
    session['device_name'] = device_name
    
    redirect_uri = url_for('github_authorized', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@app.route('/login/github/authorized')
def github_authorized():
    try:
        # Get device info from session
        device_id = session.get('device_id')
        device_name = session.get('device_name')
        
        if not device_id or not device_name:
            return jsonify({
                'success': False,
                'message': 'Device information not found'
            }), 400
            
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get('user')
        user_info = resp.json()
        
        # Get user's email
        emails_resp = oauth.github.get('user/emails')
        emails = emails_resp.json()
        primary_email = next(
            (email['email'] for email in emails if email['primary']),
            emails[0]['email']
        )
        
        # Check if user exists
        user = db.get_user_by_oauth('github', str(user_info['id']))
        
        if not user:
            # Create new user with device info
            user_id = db.create_user(
                username=user_info['login'],
                email=primary_email,
                oauth_provider='github',
                oauth_id=str(user_info['id']),
                profile_picture=user_info.get('avatar_url'),
                device_id=device_id,
                device_name=device_name
            )
        else:
            user_id = user['id']
            # Update user's device info and last login
            db.update_user_device(user_id, device_id, device_name)
            db.update_user_login(user_id)

        session['user_id'] = user_id
        
        # Clear device info from session after use
        session.pop('device_id', None)
        session.pop('device_name', None)
        
        return redirect(url_for('index'))
        
    except Exception as e:
        logging.error(f"GitHub OAuth error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Authentication failed',
            'error': str(e)
        }), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/create')
@login_required
def create():
    return render_template('create_room.html')

@app.route('/join')
@login_required
def join():
    return render_template('join_room.html')

@app.route('/create_room', methods=['POST'])
def create_room():
    data = request.json
    username = data.get('username')
    room_name = data.get('room_name')
    password = data.get('password')

    if not all([username, room_name, password]):
        return jsonify({'success': False, 'message': 'Missing required fields'})

    # Create user first
    user_id = db.create_user(username)
    if not user_id:
        return jsonify({'success': False, 'message': 'Error creating user'})

    # Create room
    room_id = db.create_room(room_name, password, user_id)
    if not room_id:
        return jsonify({'success': False, 'message': 'Error creating room'})

    # Create session
    session_id = db.create_session(user_id, room_id)
    if not session_id:
        return jsonify({'success': False, 'message': 'Error creating session'})

    session['session_id'] = session_id
    session['username'] = username

    return jsonify({'success': True, 'room_id': room_id})

@app.route('/join_room', methods=['POST'])
def join_room_endpoint():
    data = request.json
    username = data.get('username')
    room_name = data.get('room_name')
    password = data.get('password')

    if not all([username, room_name, password]):
        return jsonify({'success': False, 'message': 'Missing required fields'})

    # Verify room and password
    is_valid, room_id = db.verify_room(room_name, password)
    if not is_valid:
        return jsonify({'success': False, 'message': 'Invalid room or password'})

    # Create user
    user_id = db.create_user(username)
    if not user_id:
        return jsonify({'success': False, 'message': 'Error creating user'})

    # Create session
    session_id = db.create_session(user_id, room_id)
    if not session_id:
        return jsonify({'success': False, 'message': 'Error creating session'})

    session['session_id'] = session_id
    session['username'] = username

    return jsonify({'success': True, 'room_id': room_id})

@app.route('/available_rooms')
def get_available_rooms():
    try:
        # Get list of active rooms from database
        rooms = db.get_available_rooms()
        return jsonify({'success': True, 'rooms': rooms})
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': 'Error fetching rooms',
            'error': str(e)
        })

@app.route('/chat')
def chat():
    if 'session_id' not in session:
        return redirect('/')
        
    # Update session last accessed time
    db.update_session(session['session_id'])
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    if 'session_id' in session:
        session_data = db.get_session(session['session_id'])
        if session_data:
            user_id = session_data['user_id']
            room_id = session_data['room_id']
            db.update_user_status(user_id, 'online')
            join_room(room_id)
            emit_room_users(room_id)

@socketio.on('disconnect')
def handle_disconnect():
    if 'session_id' in session:
        session_data = db.get_session(session['session_id'])
        if session_data:
            user_id = session_data['user_id']
            room_id = session_data['room_id']
            db.update_user_status(user_id, 'offline')
            leave_room(room_id)
            emit_room_users(room_id)

@socketio.on('typing')
def handle_typing(data):
    if 'session_id' in session:
        session_data = db.get_session(session['session_id'])
        if session_data:
            user_id = session_data['user_id']
            room_id = session_data['room_id']
            is_typing = data.get('typing', False)
            db.update_user_status(user_id, 'typing' if is_typing else 'online')
            
            emit('user_typing', {
                'user_id': user_id,
                'username': session['username'],
                'typing': is_typing
            }, room=room_id, include_self=False)

@socketio.on('join')
def on_join(data):
    if 'session_id' in session:
        session_data = db.get_session(session['session_id'])
        if session_data:
            user_id = session_data['user_id']
            room_id = session_data['room_id']
            
            join_room(room_id)
            db.update_user_status(user_id, 'online')
            emit_room_users(room_id)
            
            # Load recent messages
            messages = db.get_room_messages(room_id)
            emit('load_messages', {'messages': messages})

@socketio.on('leave')
def on_leave(data):
    if 'session_id' in session:
        session_data = db.get_session(session['session_id'])
        if session_data:
            room_id = session_data['room_id']
            username = session.get('username')
            leave_room(room_id)
            emit('status', {'msg': f'{username} has left the room.'}, room=room_id)
            
            # Delete session
            db.delete_session(session['session_id'])
            session.clear()

@socketio.on('message')
def handle_message(data):
    try:
        if 'session_id' not in session:
            raise ValueError('Session expired')
            
        session_data = db.get_session(session['session_id'])
        if not session_data:
            raise ValueError('Invalid session')
            
        user_id = session_data['user_id']
        room_id = session_data['room_id']
        username = session.get('username')
        message = data.get('message')

        if not message:
            raise ValueError('Missing message')

        # Save message to database
        result = db.save_message(room_id, user_id, message)
        if not result:
            raise ValueError('Failed to process message')
            
        if result.get('success'):
            emit('message', {
                'username': username,
                'message': message,
                'encrypted': result['encrypted'],
                'created_at': result['created_at']
            }, room=room_id)
        else:
            raise ValueError(result.get('error', 'Unknown error occurred'))
    except Exception as e:
        logging.error(f"Message handling error: {str(e)}")
        emit('error', {'msg': f'Failed to send message: {str(e)}'})

@socketio.on('message_read')
def handle_message_read(data):
    try:
        if 'session_id' not in session:
            raise ValueError('Session expired')
            
        session_data = db.get_session(session['session_id'])
        if not session_data:
            raise ValueError('Invalid session')
            
        user_id = session_data['user_id']
        room_id = session_data['room_id']
        message_id = data.get('message_id')

        if not message_id:
            raise ValueError('Missing message ID')

        # Mark message as read
        if db.mark_message_as_read(message_id, user_id):
            # Get updated read status
            reads = db.get_message_reads(message_id)
            # Emit to all users in room
            emit('message_read_status', {
                'message_id': message_id,
                'read_by': [read['username'] for read in reads]
            }, room=room_id)
        else:
            raise ValueError('Failed to mark message as read')
    except Exception as e:
        logging.error(f"Message read handling error: {str(e)}")
        emit('error', {'msg': f'Failed to mark message as read: {str(e)}'})

@socketio.on('message_read_status_request')
def handle_read_status_request(data):
    try:
        if 'session_id' not in session:
            raise ValueError('Session expired')
            
        session_data = db.get_session(session['session_id'])
        if not session_data:
            raise ValueError('Invalid session')
            
        message_id = data.get('message_id')
        if not message_id:
            raise ValueError('Missing message ID')

        # Get read status details
        reads = db.get_message_reads(message_id)
        emit('message_read_status_response', {'reads': reads})
    except Exception as e:
        logging.error(f"Read status request error: {str(e)}")
        emit('error', {'msg': f'Failed to get read status: {str(e)}'})

def emit_room_users(room_id):
    """Emit updated user list to all clients in room"""
    users = db.get_room_users(room_id)
    emit('room_users', {'users': users}, room=room_id)

if __name__ == '__main__':
    local_ip = get_local_ip()
    print("\n=== Chat Server Started ===")
    print(f"Local server URL: http://{local_ip}:5000")
    print(f"Share this URL with users on your local network")
    print("===============================\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)