import os
import time
import json
import hashlib
import base64
import hmac
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
import brotli

class SecureMessagingSystem:
    def __init__(self):
        # Storage for registered users and their devices
        self.users = {}
        self.device_keys = {}
        self.sessions = {}
        self.message_queue = {}
        
    def register_user(self, username, password, device_id):
        """Register a new user with the system"""
        if username in self.users:
            return {"status": "error", "message": "User already exists"}
        
        # Generate salt for password hashing
        salt = os.urandom(16)
        
        # Create password hash using Argon2id (simulated)
        # In practice, use a proper Argon2id implementation with appropriate parameters
        password_hash = hashlib.sha256(password.encode() + salt).digest()  # Placeholder for Argon2id
        
        # Generate identity key pair (Ed25519 for signing)
        identity_private_key = ed25519.Ed25519PrivateKey.generate()
        identity_public_key = identity_private_key.public_key()
        
        # Serialize keys for storage
        identity_public_bytes = identity_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Store user information
        self.users[username] = {
            "password_hash": password_hash,
            "salt": salt,
            "identity_public_key": identity_public_bytes,
            "registered_devices": [device_id],
            "creation_time": int(time.time()),
            "last_login": None,
            "failed_attempts": 0
        }
        
        # Return the identity key for client-side storage
        identity_private_bytes = identity_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return {
            "status": "success", 
            "message": "User registered successfully",
            "identity_key": base64.b64encode(identity_private_bytes).decode('utf-8')
        }
    
    def register_device(self, username, device_id, device_name, auth_token=None):
        """Register a new device for an existing user"""
        if username not in self.users:
            return {"status": "error", "message": "User not found"}
            
        if not self._validate_auth_token(username, auth_token):
            return {"status": "error", "message": "Authentication required"}
        
        # Generate device key pair (X25519 for key exchange)
        device_private_key = x25519.X25519PrivateKey.generate()
        device_public_key = device_private_key.public_key()
        
        # Serialize public key for storage
        device_public_bytes = device_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Store device information
        device_key = f"{username}:{device_id}"
        self.device_keys[device_key] = {
            "public_key": device_public_bytes,
            "name": device_name,
            "registration_time": int(time.time()),
            "last_active": int(time.time())
        }
        
        # Add device to user's registered devices
        if device_id not in self.users[username]["registered_devices"]:
            self.users[username]["registered_devices"].append(device_id)
        
        # Return the device key for client-side storage
        device_private_bytes = device_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return {
            "status": "success",
            "message": "Device registered successfully",
            "device_key": base64.b64encode(device_private_bytes).decode('utf-8')
        }
    
    def authenticate_user(self, username, password, device_id):
        """Authenticate a user and create a session"""
        if username not in self.users:
            return {"status": "error", "message": "Invalid credentials"}
        
        user = self.users[username]
        
        # Verify password
        password_hash = hashlib.sha256(password.encode() + user["salt"]).digest()
        if not hmac.compare_digest(password_hash, user["password_hash"]):
            # Increment failed attempts
            user["failed_attempts"] += 1
            if user["failed_attempts"] >= 5:
                # Lock account after 5 failed attempts
                user["locked"] = True
                return {"status": "error", "message": "Account locked due to multiple failed attempts"}
            return {"status": "error", "message": "Invalid credentials"}
        
        # Reset failed attempts
        user["failed_attempts"] = 0
        
        # Check if device is registered
        if device_id not in user["registered_devices"]:
            return {"status": "error", "message": "Unrecognized device. Please register this device first."}
        
        # Generate session token
        session_token = secrets.token_hex(32)
        session_expiry = int(time.time()) + 86400  # 24 hours
        
        # Store session
        self.sessions[session_token] = {
            "username": username,
            "device_id": device_id,
            "created": int(time.time()),
            "expires": session_expiry,
            "last_active": int(time.time())
        }
        
        # Update user's last login time
        user["last_login"] = int(time.time())
        
        return {
            "status": "success",
            "message": "Authentication successful",
            "session_token": session_token,
            "expires": session_expiry
        }
    
    def _validate_auth_token(self, username, token):
        """Validate a session token"""
        if not token or token not in self.sessions:
            return False
        
        session = self.sessions[token]
        if session["username"] != username:
            return False
        
        if session["expires"] < int(time.time()):
            # Session expired
            del self.sessions[token]
            return False
        
        # Update last active time
        session["last_active"] = int(time.time())
        return True
    
    def initiate_secure_channel(self, sender_username, sender_device_id, recipient_username, recipient_device_id, auth_token):
        """Initiate a secure channel between two devices"""
        # Validate authentication
        if not self._validate_auth_token(sender_username, auth_token):
            return {"status": "error", "message": "Authentication required"}
        
        # Check if users and devices exist
        sender_device_key = f"{sender_username}:{sender_device_id}"
        recipient_device_key = f"{recipient_username}:{recipient_device_id}"
        
        if sender_device_key not in self.device_keys:
            return {"status": "error", "message": "Sender device not registered"}
        
        if recipient_device_key not in self.device_keys:
            return {"status": "error", "message": "Recipient device not registered"}
        
        # Generate a unique channel ID
        channel_id = secrets.token_hex(16)
        
        # In a real system, we would now exchange keys using the Double Ratchet algorithm
        # For this implementation, we'll create a simpler key exchange model
        
        return {
            "status": "success",
            "message": "Secure channel initiated",
            "channel_id": channel_id,
            "recipient_public_key": base64.b64encode(self.device_keys[recipient_device_key]["public_key"]).decode('utf-8')
        }
    
    def send_message(self, sender_username, sender_device_id, recipient_username, recipient_device_id, 
                    message_content, auth_token, channel_id=None):
        """Send an encrypted message from one user to another"""
        # Validate authentication
        if not self._validate_auth_token(sender_username, auth_token):
            return {"status": "error", "message": "Authentication required"}
        
        # Create or retrieve channel
        if not channel_id:
            channel_result = self.initiate_secure_channel(
                sender_username, sender_device_id, 
                recipient_username, recipient_device_id, 
                auth_token
            )
            if channel_result["status"] == "error":
                return channel_result
            channel_id = channel_result["channel_id"]
        
        # In a real implementation, we would use the Double Ratchet algorithm for key derivation
        # For simplicity, we'll use a simulated encryption method
        
        # Compress message if it's text
        compressed_content = brotli.compress(message_content.encode('utf-8'))
        
        # Generate a message key
        message_key = os.urandom(32)
        
        # Encrypt the message
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(message_key)
        encrypted_content = chacha.encrypt(nonce, compressed_content, None)
        
        # Construct the encrypted message
        encrypted_message = {
            "channel_id": channel_id,
            "sender": sender_username,
            "recipient": recipient_username,
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "content": base64.b64encode(encrypted_content).decode('utf-8'),
            "message_id": secrets.token_hex(16)
        }
        
        # Queue the message for delivery
        recipient_queue_key = f"{recipient_username}:{recipient_device_id}"
        if recipient_queue_key not in self.message_queue:
            self.message_queue[recipient_queue_key] = []
        
        self.message_queue[recipient_queue_key].append({
            "message": encrypted_message,
            # In a real implementation, the message key would be encrypted with the recipient's public key
            "key": base64.b64encode(message_key).decode('utf-8')
        })
        
        return {
            "status": "success",
            "message": "Message sent successfully",
            "message_id": encrypted_message["message_id"]
        }
    
    def receive_messages(self, username, device_id, auth_token):
        """Retrieve pending messages for a user's device"""
        # Validate authentication
        if not self._validate_auth_token(username, auth_token):
            return {"status": "error", "message": "Authentication required"}
        
        # Retrieve messages from queue
        queue_key = f"{username}:{device_id}"
        if queue_key not in self.message_queue or not self.message_queue[queue_key]:
            return {
                "status": "success",
                "message": "No new messages",
                "messages": []
            }
        
        messages = self.message_queue[queue_key]
        
        # Clear the queue after retrieval
        self.message_queue[queue_key] = []
        
        return {
            "status": "success",
            "message": f"Retrieved {len(messages)} messages",
            "messages": messages
        }
    
    def decrypt_message(self, encrypted_message, message_key, recipient_private_key_b64):
        """
        Client-side message decryption
        Note: In a real implementation, this would happen on the client device
        """
        try:
            # Decode the message key
            message_key = base64.b64decode(message_key)
            
            # Decode message components
            nonce = base64.b64decode(encrypted_message["nonce"])
            encrypted_content = base64.b64decode(encrypted_message["content"])
            
            # Decrypt the message
            chacha = ChaCha20Poly1305(message_key)
            decrypted_content = chacha.decrypt(nonce, encrypted_content, None)
            
            # Decompress the message
            message_text = brotli.decompress(decrypted_content).decode('utf-8')
            
            return {
                "status": "success", 
                "message": "Message decrypted successfully",
                "sender": encrypted_message["sender"],
                "timestamp": encrypted_message["timestamp"],
                "content": message_text
            }
        except Exception as e:
            return {"status": "error", "message": f"Decryption failed: {str(e)}"}