# Encrypted Local Network Chat

A real-time chat application that runs on your local network with SHA-256 message encryption, built with Python, Flask, and WebSocket.

## Features

- Real-time messaging using WebSocket
- SHA-256 encryption for messages
- Room-based chat system
- Modern WhatsApp-like interface
- Local network deployment
- Join/leave notifications
- Message encryption display

## Requirements

- Python 3.7+
- pip (Python package manager)

## Installation

1. Clone this repository or download the files
2. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

1. Start the server:

```bash
python app.py
```

2. Access the chat application:

   - Open your web browser
   - Go to `http://localhost:5000` or `http://<your-local-ip>:5000`
   - Other users on the same network can access using your computer's local IP address

3. To join a chat:

   - Enter your username
   - Enter a room ID (create a new room or join an existing one)
   - Click "Join"

4. Start chatting:
   - Type your message and press Enter or click Send
   - Messages are automatically encrypted using SHA-256
   - You can see both the original and encrypted message

## Security Note

This application uses SHA-256 for message hashing. While messages are encrypted, please note that this is a basic implementation for educational purposes. For production use, you should implement end-to-end encryption and additional security measures.

## Network Access

By default, the application runs on `0.0.0.0:5000`, making it accessible to all devices on your local network. Make sure your firewall settings allow this connection.
