from flask import Flask, render_template, request, session, jsonify, redirect
from flask_socketio import SocketIO, emit, join_room, leave_room
import hashlib
import secrets
import socket
from database import Database
from datetime import datetime
import logging

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
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app)
db = Database()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create')
def create_room_page():
    return render_template('create_room.html')

@app.route('/join')
def join_room_page():
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

    session['user_id'] = user_id
    session['room_id'] = room_id
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

    session['user_id'] = user_id
    session['room_id'] = room_id
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
    if 'user_id' not in session:
        return redirect('/')
    return render_template('chat.html')

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        db.update_user_status(session['user_id'], 'online')
        if 'room_id' in session:
            join_room(session['room_id'])
            # Send updated user list to all clients in room
            emit_room_users(session['room_id'])

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        db.update_user_status(session['user_id'], 'offline')
        if 'room_id' in session:
            leave_room(session['room_id'])
            # Send updated user list to all clients in room
            emit_room_users(session['room_id'])

@socketio.on('typing')
def handle_typing(data):
    if all(key in session for key in ['user_id', 'room_id', 'username']):
        is_typing = data.get('typing', False)
        db.update_user_status(session['user_id'], 'typing' if is_typing else 'online')
        
        # Emit typing status to all users in room except sender
        emit('user_typing', {
            'user_id': session['user_id'],
            'username': session['username'],
            'typing': is_typing
        }, room=session['room_id'], include_self=False)

def emit_room_users(room_id):
    """Emit updated user list to all clients in room"""
    users = db.get_room_users(room_id)
    emit('room_users', {'users': users}, room=room_id)

@socketio.on('join')
def on_join(data):
    if all(key in session for key in ['user_id', 'room_id', 'username']):
        room = session['room_id']
        username = session['username']
        join_room(room)
        
        # Update user status and emit to room
        db.update_user_status(session['user_id'], 'online')
        emit_room_users(room)
        
        # Load recent messages
        messages = db.get_room_messages(room)
        emit('load_messages', {'messages': messages})

@socketio.on('leave')
def on_leave(data):
    room = session.get('room_id')
    username = session.get('username')
    if room:
        leave_room(room)
        emit('status', {'msg': f'{username} has left the room.'}, room=room)
    session.clear()

@socketio.on('message')
def handle_message(data):
    try:
        user_id = session.get('user_id')
        room = session.get('room_id')
        username = session.get('username')
        message = data.get('message')

        if not all([user_id, room, username, message]):
            raise ValueError('Session expired or missing message')

        # Save message to database (it will be encrypted inside save_message)
        result = db.save_message(room, user_id, message)
        if not result:
            raise ValueError('Failed to process message')
            
        if result.get('success'):
            emit('message', {
                'username': username,
                'message': message,
                'encrypted': result['encrypted'],
                'created_at': result['created_at']
            }, room=room)
        else:
            raise ValueError(result.get('error', 'Unknown error occurred'))
    except Exception as e:
        logging.error(f"Message handling error: {str(e)}")
        emit('error', {'msg': f'Failed to send message: {str(e)}'})

if __name__ == '__main__':
    local_ip = get_local_ip()
    print("\n=== Chat Server Started ===")
    print(f"Local server URL: http://{local_ip}:5000")
    print(f"Share this URL with users on your local network")
    print("===============================\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)