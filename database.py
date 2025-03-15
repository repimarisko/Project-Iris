import mysql.connector
from mysql.connector import Error
import hashlib
import os
from dotenv import load_dotenv
import base64
import logging
from datetime import datetime
from cryptography.fernet import Fernet
import json

# Load environment variables
load_dotenv()

class Database:
    def __init__(self):
        self.connection = None
        self.cursor = None
        
        self.setup_encryption()
        self.connect()
        self.create_tables()

    def setup_encryption(self):
        """Setup encryption with room-based keys"""
        try:
            # Master key for room key encryption
            master_key = os.getenv('ENCRYPTION_KEY')
            if not master_key:
                master_key = Fernet.generate_key()
                print("\nIMPORTANT: Add this encryption key to your .env file:")
                print(f"ENCRYPTION_KEY={master_key.decode()}\n")
            elif isinstance(master_key, str):
                master_key = master_key.encode()
            
            self.master_cipher = Fernet(master_key)
            self.room_keys = {}
        except Exception as e:
            logging.error(f"Encryption setup error: {str(e)}")
            master_key = Fernet.generate_key()
            print("\nERROR: Invalid encryption key. Using new key:")
            print(f"ENCRYPTION_KEY={master_key.decode()}")
            print("Please add this key to your .env file and restart the application.\n")
            self.master_cipher = Fernet(master_key)

    def generate_room_key(self, room_id, password):
        """Generate a unique encryption key for a room based on room ID and password"""
        try:
            # Create a deterministic room key that will always be the same for the same room_id and password
            key_material = f"{room_id}:{password}".encode()
            key_hash = hashlib.sha256(key_material).digest()
            room_key = base64.urlsafe_b64encode(key_hash)
            
            # Encrypt room key with master key for storage
            encrypted_key = self.master_cipher.encrypt(room_key)
            return room_key, encrypted_key
        except Exception as e:
            logging.error(f"Room key generation error for room {room_id}: {str(e)}")
            return None, None

    def get_room_key(self, room_id, password=None):
        """Get or generate room encryption key"""
        try:
            # Check cache first
            if room_id in self.room_keys:
                return self.room_keys[room_id]
                
            # Get room details from database
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute("SELECT password_hash FROM rooms WHERE id = %s", (room_id,))
            room = cursor.fetchone()
            cursor.close()
            
            if not room:
                logging.error(f"Room {room_id} not found")
                return None
            
            # Generate key using password hash
            room_key, encrypted_key = self.generate_room_key(room_id, room['password_hash'])
            if not room_key:
                logging.error(f"Failed to generate key for room {room_id}")
                return None
                
            # Cache the key
            self.room_keys[room_id] = room_key
            
            # Update encryption key in database
            try:
                cursor = self.connection.cursor()
                cursor.execute(
                    "UPDATE rooms SET encryption_key = %s WHERE id = %s",
                    (encrypted_key.decode(), room_id)
                )
                self.connection.commit()
                cursor.close()
            except Error as e:
                logging.warning(f"Failed to update encryption key in database: {str(e)}")
            
            return room_key
        except Exception as e:
            logging.error(f"Get room key error: {str(e)}")
            return None

    def encrypt_message(self, message, room_id):
        """Encrypt a message using room-specific key"""
        try:
            if not isinstance(message, str):
                raise ValueError(f"Message must be string, got {type(message)}")
            if not message:
                raise ValueError("Message cannot be empty")
            if not room_id:
                raise ValueError("Room ID is required")
            
            room_key = self.get_room_key(room_id)
            if not room_key:
                raise ValueError(f"Room key not found for room {room_id}")
            
            try:
                # Create message package with metadata
                message_data = {
                    'content': message,
                    'timestamp': datetime.now().isoformat(),
                    'room_id': room_id  # Include room_id for verification during decryption
                }
                
                # Convert to JSON and encode
                message_json = json.dumps(message_data)
                message_bytes = message_json.encode('utf-8')
                
                # Encrypt
                cipher = Fernet(room_key)
                encrypted_bytes = cipher.encrypt(message_bytes)
                
                # Convert to storable string
                return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
            except Exception as e:
                logging.error(f"Failed to encrypt message for room {room_id}: {str(e)}")
                return None
        except Exception as e:
            logging.error(f"Message encryption error for room {room_id}: {str(e)}")
            return None

    def decrypt_message(self, encrypted_message, room_id):
        """Decrypt a message using room-specific key"""
        try:
            if not isinstance(encrypted_message, str):
                raise ValueError(f"Encrypted message must be string, got {type(encrypted_message)}")
            if not encrypted_message:
                raise ValueError("Encrypted message cannot be empty")
            if not room_id:
                raise ValueError("Room ID is required")
            
            room_key = self.get_room_key(room_id)
            if not room_key:
                raise ValueError(f"Room key not found for room {room_id}")
            
            try:
                # Decode from storage format
                encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
                
                # Decrypt
                cipher = Fernet(room_key)
                decrypted_bytes = cipher.decrypt(encrypted_bytes)
                
                # Parse JSON
                message_data = json.loads(decrypted_bytes.decode('utf-8'))
                
                # Verify room_id if present (for newer messages)
                if 'room_id' in message_data and message_data['room_id'] != room_id:
                    raise ValueError("Message room ID mismatch")
                
                return message_data['content']
            except json.JSONDecodeError as e:
                logging.error(f"Failed to decode message JSON in room {room_id}: {str(e)}")
                return None
            except Exception as e:
                logging.error(f"Failed to decrypt message in room {room_id}: {str(e)}")
                return None
        except Exception as e:
            logging.error(f"Message decryption error for room {room_id}: {str(e)}")
            return None

    def connect(self):
        """Connect to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'root'),
                password=os.getenv('DB_PASSWORD', ''),
                database=os.getenv('DB_NAME', 'iris_chat')
            )
            if self.connection.is_connected():
                self.cursor = self.connection.cursor(dictionary=True)
                self.create_tables()
            else:
                print("Failed to connect to MySQL database")
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            if self.connection is not None and self.connection.is_connected():
                self.connection.close()

    def create_tables(self):
        if not self.cursor:
            print("Database not connected. Cannot create tables.")
            return
            
        try:
            # Create users table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(36) PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    status ENUM('online', 'offline', 'typing') DEFAULT 'offline',
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create rooms table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS rooms (
                    id VARCHAR(36) PRIMARY KEY,
                    room_name VARCHAR(50) NOT NULL,
                    password_hash VARCHAR(256) NOT NULL,
                    creator_id VARCHAR(36),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    encryption_key TEXT,
                    FOREIGN KEY (creator_id) REFERENCES users(id)
                )
            """)

            # Create messages table
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id VARCHAR(36) PRIMARY KEY,
                    room_id VARCHAR(36),
                    user_id VARCHAR(36),
                    message_encrypted TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (room_id) REFERENCES rooms(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            self.connection.commit()
        except Error as e:
            print(f"Error creating tables: {e}")

    def create_user(self, username):
        if not self.cursor:
            print("Database not connected. Cannot create user.")
            return None
        try:
            user_id = hashlib.sha256(username.encode()).hexdigest()[:36]
            query = "INSERT IGNORE INTO users (id, username) VALUES (%s, %s)"
            self.cursor.execute(query, (user_id, username))
            self.connection.commit()
            return user_id
        except Error as e:
            print(f"Error creating user: {e}")
            return None

    def create_room(self, room_name, password, creator_id):
        """Create a new room with its encryption key"""
        if not self.cursor:
            print("Database not connected. Cannot create room.")
            return None
        try:
            room_id = hashlib.sha256(room_name.encode()).hexdigest()[:36]
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Generate and store room key
            room_key, encrypted_key = self.generate_room_key(room_id, password)
            if not room_key or not encrypted_key:
                raise ValueError("Failed to generate room key")
            
            query = """
                INSERT INTO rooms (id, room_name, password_hash, creator_id, encryption_key) 
                VALUES (%s, %s, %s, %s, %s)
            """
            self.cursor.execute(query, (room_id, room_name, password_hash, creator_id, encrypted_key.decode()))
            self.connection.commit()
            
            # Cache the room key
            self.room_keys[room_id] = room_key
            return room_id
        except Error as e:
            print(f"Error creating room: {e}")
            return None

    def verify_room(self, room_name, password):
        """Verify room credentials and setup encryption key"""
        if not self.cursor:
            print("Database not connected. Cannot verify room.")
            return False, None
        try:
            # Get room details including encryption key
            query = "SELECT id, password_hash FROM rooms WHERE room_name = %s"
            self.cursor.execute(query, (room_name,))
            room = self.cursor.fetchone()
            
            if not room:
                return False, None
                
            # Verify password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if room['password_hash'] != password_hash:
                return False, None
                
            # Setup room encryption key using original password
            room_id = room['id']
            room_key, encrypted_key = self.generate_room_key(room_id, password)
            if room_key:
                self.room_keys[room_id] = room_key
                
                # Update encryption key in database
                try:
                    cursor = self.connection.cursor()
                    cursor.execute(
                        "UPDATE rooms SET encryption_key = %s WHERE id = %s",
                        (encrypted_key.decode(), room_id)
                    )
                    self.connection.commit()
                    cursor.close()
                except Error as e:
                    logging.warning(f"Failed to update encryption key in database: {str(e)}")
                
                return True, room_id
                
            return False, None
        except Error as e:
            logging.error(f"Error verifying room: {str(e)}")
            return False, None

    def save_message(self, room_id, user_id, message):
        """Save an encrypted message to the database"""
        try:
            if not all([room_id, user_id, message]):
                raise ValueError("Missing required fields: room_id, user_id, or message")
                
            encrypted_message = self.encrypt_message(message, room_id)
            if not encrypted_message:
                raise ValueError("Failed to encrypt message")

            message_id = hashlib.sha256(f"{room_id}{user_id}{message}".encode()).hexdigest()[:36]
            current_time = datetime.now()
            
            cursor = self.connection.cursor()
            query = """
                INSERT INTO messages (id, room_id, user_id, message_encrypted, created_at)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (message_id, room_id, user_id, encrypted_message, current_time))
            self.connection.commit()
            cursor.close()
            
            return {
                'success': True,
                'message': message,
                'encrypted': encrypted_message,
                'created_at': current_time.isoformat()
            }
        except Exception as e:
            logging.error(f"Save message error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def get_room_messages(self, room_id, limit=50):
        """Get and decrypt messages for a room"""
        try:
            if not room_id:
                raise ValueError("Room ID is required")
                
            cursor = self.connection.cursor(dictionary=True)
            query = """
                SELECT m.id, m.message_encrypted, m.created_at, u.username
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.room_id = %s
                ORDER BY m.created_at DESC
                LIMIT %s
            """
            cursor.execute(query, (room_id, limit))
            messages = cursor.fetchall()
            cursor.close()

            # Decrypt messages
            formatted_messages = []
            for message in messages:
                try:
                    decrypted = self.decrypt_message(message['message_encrypted'], room_id)
                    if decrypted is None:
                        logging.error(f"Failed to decrypt message {message['id']} in room {room_id}")
                        formatted_messages.append({
                            'id': message['id'],
                            'username': message['username'],
                            'message': "[Message could not be decrypted]",
                            'encrypted': message['message_encrypted'],
                            'created_at': message['created_at'].isoformat() if isinstance(message['created_at'], datetime) else message['created_at'],
                            'error': True
                        })
                        continue
                        
                    formatted_messages.append({
                        'id': message['id'],
                        'username': message['username'],
                        'message': decrypted,
                        'encrypted': message['message_encrypted'],
                        'created_at': message['created_at'].isoformat() if isinstance(message['created_at'], datetime) else message['created_at']
                    })
                except Exception as e:
                    logging.error(f"Error processing message {message['id']} in room {room_id}: {str(e)}")
                    formatted_messages.append({
                        'id': message['id'],
                        'username': message['username'],
                        'message': "[Error: Message processing failed]",
                        'encrypted': message['message_encrypted'],
                        'created_at': message['created_at'].isoformat() if isinstance(message['created_at'], datetime) else message['created_at'],
                        'error': True,
                        'error_details': str(e)
                    })

            return formatted_messages
        except Exception as e:
            logging.error(f"Get messages error for room {room_id}: {str(e)}")
            return []

    def get_available_rooms(self):
        if not self.cursor:
            print("Database not connected. Cannot get available rooms.")
            return []
        try:
            query = """
                SELECT r.room_name as name, u.username as creator, 
                       r.created_at as created_at
                FROM rooms r
                JOIN users u ON r.creator_id = u.id
                ORDER BY r.created_at DESC
            """
            self.cursor.execute(query)
            rooms = self.cursor.fetchall()
            
            # Convert datetime objects to ISO format strings
            for room in rooms:
                if isinstance(room['created_at'], datetime):
                    room['created_at'] = room['created_at'].isoformat()
            
            return rooms
        except Error as e:
            print(f"Error getting available rooms: {e}")
            return []

    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.connection and self.connection.is_connected():
                self.connection.close()
        except Error as e:
            print(f"Error closing connection: {e}")

    def update_user_status(self, user_id, status):
        """Update user status (online/offline/typing)"""
        if not self.cursor:
            print("Database not connected. Cannot update user status.")
            return False
        try:
            current_time = datetime.now()
            query = """
                UPDATE users 
                SET status = %s, last_seen = %s 
                WHERE id = %s
            """
            self.cursor.execute(query, (status, current_time, user_id))
            self.connection.commit()
            return True
        except Error as e:
            logging.error(f"Error updating user status: {str(e)}")
            return False

    def get_room_users(self, room_id):
        """Get all users in a room with their status"""
        if not self.cursor:
            print("Database not connected. Cannot get room users.")
            return []
        try:
            query = """
                SELECT DISTINCT u.id, u.username, u.status, u.last_seen
                FROM users u
                JOIN messages m ON u.id = m.user_id
                WHERE m.room_id = %s
                ORDER BY u.last_seen DESC
            """
            self.cursor.execute(query, (room_id,))
            users = self.cursor.fetchall()
            
            # Convert datetime objects to ISO format strings
            for user in users:
                if isinstance(user['last_seen'], datetime):
                    user['last_seen'] = user['last_seen'].isoformat()
            
            return users
        except Error as e:
            logging.error(f"Error getting room users: {str(e)}")
            return [] 