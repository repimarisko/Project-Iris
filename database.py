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
import secrets
import uuid

# Load environment variables
load_dotenv()

class Database:
    def __init__(self):
        self.connection = None
        self.cursor = None
        
        self.setup_encryption()
        if self.connect():
            print("Creating database tables...")
            self.create_tables()
        else:
            print("Failed to connect to database")

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
            if self.connection is not None and self.connection.is_connected():
                return True

            self.connection = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'root'),
                password=os.getenv('DB_PASSWORD', ''),
                database=os.getenv('DB_NAME', 'iris_chat')
            )
            if self.connection.is_connected():
                self.cursor = self.connection.cursor(dictionary=True)
                print("Successfully connected to MySQL database")
                return True
            else:
                print("Failed to connect to MySQL database")
                return False
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            if self.connection is not None and self.connection.is_connected():
                self.connection.close()
            return False

    def ensure_connection(self):
        """Ensure database connection is active, reconnect if needed"""
        try:
            if self.connection is None or not self.connection.is_connected():
                print("Database connection lost, attempting to reconnect...")
                if self.connect():
                    self.create_tables()
                    return True
                return False
            return True
        except Error as e:
            print(f"Error checking connection: {e}")
            return False

    def execute_query(self, query, params=None):
        """Execute a query with connection check and retry"""
        try:
            if not self.ensure_connection():
                raise Error("Could not establish database connection")
            
            if self.cursor is None:
                self.cursor = self.connection.cursor(dictionary=True)
            
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
                
            return True
        except Error as e:
            print(f"Error executing query: {e}")
            return False

    def get_user_by_email(self, email):
        """Get user by email with connection retry"""
        try:
            if not self.ensure_connection():
                return None
                
            self.cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            return self.cursor.fetchone()
        except Error as e:
            print(f"Error getting user by email: {e}")
            return None

    def create_user(self, username, email=None, password_hash=None, oauth_provider=None, oauth_id=None, profile_picture=None, device_id=None, device_name=None):
        """Create new user with connection retry"""
        try:
            if not self.ensure_connection():
                raise Error("Database connection failed")

            user_id = str(uuid.uuid4())
            query = """
                INSERT INTO users (
                    id, username, email, password_hash, oauth_provider, oauth_id, 
                    profile_picture, device_id, device_name, created_at, last_login
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            """
            params = (
                user_id, username, email, password_hash, oauth_provider, oauth_id,
                profile_picture, device_id, device_name
            )
            
            if not self.execute_query(query, params):
                raise Error("Failed to execute create user query")
                
            self.connection.commit()
            return user_id
        except Error as e:
            print(f"Error creating user: {e}")
            if self.connection:
                self.connection.rollback()
            return None

    def get_user_by_oauth(self, oauth_provider, oauth_id):
        """Get user by OAuth credentials"""
        try:
            if not self.ensure_connection():
                return None
                
            query = "SELECT * FROM users WHERE oauth_provider = %s AND oauth_id = %s"
            self.cursor.execute(query, (oauth_provider, oauth_id))
            return self.cursor.fetchone()
        except Error as e:
            print(f"Error getting user by OAuth: {e}")
            return None

    def update_user_login(self, user_id):
        """Update user's last login time"""
        try:
            self.cursor.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                (user_id,)
            )
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Error updating user login: {e}")
            return False

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
                INSERT INTO rooms (id, name, password_hash, created_by, encryption_key) 
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
            query = "SELECT id, password_hash FROM rooms WHERE name = %s"
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
                INSERT INTO messages (id, room_id, user_id, content, created_at)
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
        """Get and decrypt messages for a room with read status"""
        try:
            if not room_id:
                raise ValueError("Room ID is required")
                
            cursor = self.connection.cursor(dictionary=True)
            query = """
                SELECT 
                    m.id, 
                    m.content, 
                    m.created_at, 
                    u.username,
                    GROUP_CONCAT(DISTINCT r.username) as read_by
                FROM messages m
                JOIN users u ON m.user_id = u.id
                LEFT JOIN message_reads mr ON m.id = mr.message_id
                LEFT JOIN users r ON mr.user_id = r.id
                WHERE m.room_id = %s
                GROUP BY m.id
                ORDER BY m.created_at DESC
                LIMIT %s
            """
            cursor.execute(query, (room_id, limit))
            messages = cursor.fetchall()
            cursor.close()

            # Decrypt messages and format read_by
            formatted_messages = []
            for message in messages:
                try:
                    decrypted = self.decrypt_message(message['content'], room_id)
                    read_by = message['read_by'].split(',') if message['read_by'] else []
                    
                    if decrypted is None:
                        logging.error(f"Failed to decrypt message {message['id']} in room {room_id}")
                        formatted_messages.append({
                            'id': message['id'],
                            'username': message['username'],
                            'message': "[Message could not be decrypted]",
                            'encrypted': message['content'],
                            'created_at': message['created_at'].isoformat() if isinstance(message['created_at'], datetime) else message['created_at'],
                            'read_by': read_by,
                            'error': True
                        })
                        continue
                        
                    formatted_messages.append({
                        'id': message['id'],
                        'username': message['username'],
                        'message': decrypted,
                        'encrypted': message['content'],
                        'created_at': message['created_at'].isoformat() if isinstance(message['created_at'], datetime) else message['created_at'],
                        'read_by': read_by
                    })
                except Exception as e:
                    logging.error(f"Error processing message {message['id']} in room {room_id}: {str(e)}")
                    formatted_messages.append({
                        'id': message['id'],
                        'username': message['username'],
                        'message': "[Error: Message processing failed]",
                        'encrypted': message['content'],
                        'created_at': message['created_at'].isoformat() if isinstance(message['created_at'], datetime) else message['created_at'],
                        'read_by': [],
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
                SELECT r.name as name, u.username as creator, 
                       r.created_at as created_at
                FROM rooms r
                JOIN users u ON r.created_by = u.id
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

    def create_session(self, user_id, room_id):
        """Create a new session"""
        try:
            session_id = secrets.token_hex(32)  # 64 characters
            query = """
                INSERT INTO sessions (id, user_id, room_id)
                VALUES (%s, %s, %s)
            """
            self.cursor.execute(query, (session_id, user_id, room_id))
            self.connection.commit()
            return session_id
        except Error as e:
            print(f"Error creating session: {e}")
            return None

    def get_session(self, session_id):
        """Get session details"""
        try:
            query = """
                SELECT user_id, room_id
                FROM sessions
                WHERE id = %s
            """
            self.cursor.execute(query, (session_id,))
            return self.cursor.fetchone()
        except Error as e:
            print(f"Error getting session: {e}")
            return None

    def update_session(self, session_id):
        """Update session last accessed time"""
        try:
            query = """
                UPDATE sessions
                SET last_accessed = CURRENT_TIMESTAMP
                WHERE id = %s
            """
            self.cursor.execute(query, (session_id,))
            self.connection.commit()
            return True
        except Error as e:
            print(f"Error updating session: {e}")
            return False

    def delete_session(self, session_id):
        """Delete a session"""
        try:
            query = "DELETE FROM sessions WHERE id = %s"
            self.cursor.execute(query, (session_id,))
            self.connection.commit()
            return True
        except Error as e:
            print(f"Error deleting session: {e}")
            return False

    def mark_message_as_read(self, message_id, user_id):
        """Mark a message as read by a user"""
        try:
            query = """
                INSERT IGNORE INTO message_reads (message_id, user_id)
                VALUES (%s, %s)
            """
            self.cursor.execute(query, (message_id, user_id))
            self.connection.commit()
            return True
        except Error as e:
            logging.error(f"Error marking message as read: {str(e)}")
            return False

    def get_message_reads(self, message_id):
        """Get list of users who have read a message"""
        try:
            query = """
                SELECT u.username, mr.read_at
                FROM message_reads mr
                JOIN users u ON mr.user_id = u.id
                WHERE mr.message_id = %s
                ORDER BY mr.read_at ASC
            """
            self.cursor.execute(query, (message_id,))
            reads = self.cursor.fetchall()
            
            # Convert datetime objects to ISO format strings
            for read in reads:
                if isinstance(read['read_at'], datetime):
                    read['read_at'] = read['read_at'].isoformat()
            
            return reads
        except Error as e:
            logging.error(f"Error getting message reads: {str(e)}")
            return []

    def update_user_device(self, user_id, device_id, device_name):
        """Update user's device information"""
        try:
            self.cursor.execute('''
                UPDATE users 
                SET device_id = ?, device_name = ?
                WHERE id = ?
            ''', (device_id, device_name, user_id))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"Error updating user device: {e}")
            return False

    def get_user_devices(self, user_id):
        """Get user's device information"""
        try:
            self.cursor.execute('''
                SELECT device_id, device_name
                FROM users
                WHERE id = ?
            ''', (user_id,))
            return self.cursor.fetchone()
        except Exception as e:
            print(f"Error getting user devices: {e}")
            return None

    def create_tables(self):
        """Create database tables"""
        try:
            if not self.ensure_connection():
                raise Error("Could not establish database connection")

            # Drop existing tables in reverse order of dependencies
            drop_tables_queries = [
                "DROP TABLE IF EXISTS message_reads",
                "DROP TABLE IF EXISTS sessions",
                "DROP TABLE IF EXISTS messages",
                "DROP TABLE IF EXISTS rooms",
                "DROP TABLE IF EXISTS users"
            ]

            for query in drop_tables_queries:
                if not self.execute_query(query):
                    raise Error(f"Failed to execute: {query}")

            # Create users table with auth info
            if not self.execute_query('''
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(36) PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    password_hash VARCHAR(255),
                    oauth_provider VARCHAR(20),
                    oauth_id VARCHAR(255),
                    profile_picture VARCHAR(255),
                    device_id VARCHAR(100),
                    device_name VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    last_seen TIMESTAMP NULL,
                    status VARCHAR(20) DEFAULT 'offline'
                )
            '''): 
                raise Error("Failed to create users table")

            # Create rooms table
            if not self.execute_query('''
                CREATE TABLE IF NOT EXISTS rooms (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    encryption_key TEXT,
                    created_by VARCHAR(36),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )
            '''):
                raise Error("Failed to create rooms table")

            # Create messages table
            if not self.execute_query('''
                CREATE TABLE IF NOT EXISTS messages (
                    id VARCHAR(36) PRIMARY KEY,
                    room_id VARCHAR(36),
                    user_id VARCHAR(36),
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (room_id) REFERENCES rooms(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            '''):
                raise Error("Failed to create messages table")

            # Create sessions table
            if not self.execute_query('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id VARCHAR(64) PRIMARY KEY,
                    user_id VARCHAR(36),
                    room_id VARCHAR(36),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (room_id) REFERENCES rooms(id)
                )
            '''):
                raise Error("Failed to create sessions table")

            # Create message_reads table
            if not self.execute_query('''
                CREATE TABLE IF NOT EXISTS message_reads (
                    message_id VARCHAR(36),
                    user_id VARCHAR(36),
                    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (message_id, user_id),
                    FOREIGN KEY (message_id) REFERENCES messages(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            '''):
                raise Error("Failed to create message_reads table")

            self.connection.commit()
            print("All tables created successfully")
            return True
        except Error as e:
            print(f"Error creating tables: {e}")
            if self.connection:
                self.connection.rollback()
            return False 