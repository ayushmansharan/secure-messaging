import time
import base64
import json
from server import SecureMessagingSystem  # Import the server class for local testing

class SecureMessagingClient:
    def __init__(self, server_connection, username, device_id):
        self.server = server_connection
        self.username = username
        self.device_id = device_id
        self.session_token = None
        self.private_keys = {}
        self.contacts = {}
        self.active_channels = {}
    
    def register_account(self, password):
        """Register a new user account"""
        result = self.server.register_user(self.username, password, self.device_id)
        if result["status"] == "success":
            # Store identity key securely
            self.private_keys["identity"] = result["identity_key"]
        return result
    
    def login(self, password):
        """Log into the account"""
        result = self.server.authenticate_user(self.username, password, self.device_id)
        if result["status"] == "success":
            self.session_token = result["session_token"]
        return result
    
    def register_device(self, device_name):
        """Register this device with the server"""
        if not self.session_token:
            return {"status": "error", "message": "Not authenticated"}
        
        result = self.server.register_device(
            self.username, 
            self.device_id, 
            device_name, 
            self.session_token
        )
        
        if result["status"] == "success":
            # Store device key securely
            self.private_keys["device"] = result["device_key"]
        
        return result
    
    def establish_secure_channel(self, recipient_username, recipient_device_id):
        """Establish a secure channel with another user"""
        if not self.session_token:
            return {"status": "error", "message": "Not authenticated"}
        
        result = self.server.initiate_secure_channel(
            self.username,
            self.device_id,
            recipient_username,
            recipient_device_id,
            self.session_token
        )
        
        if result["status"] == "success":
            # Store channel information
            channel_id = result["channel_id"]
            self.active_channels[channel_id] = {
                "recipient": recipient_username,
                "recipient_device": recipient_device_id,
                "recipient_key": result["recipient_public_key"],
                "created_at": int(time.time())
            }
        
        return result
    
    def send_message(self, recipient_username, recipient_device_id, message_text):
        """Send an encrypted message to another user"""
        if not self.session_token:
            return {"status": "error", "message": "Not authenticated"}
        
        # Find or create a channel
        channel_id = None
        for cid, channel in self.active_channels.items():
            if (channel["recipient"] == recipient_username and 
                channel["recipient_device"] == recipient_device_id):
                channel_id = cid
                break
        
        # Send the message through the server
        result = self.server.send_message(
            self.username,
            self.device_id,
            recipient_username,
            recipient_device_id,
            message_text,
            self.session_token,
            channel_id
        )
        
        return result
    
    def check_messages(self):
        """Check for new messages"""
        if not self.session_token:
            return {"status": "error", "message": "Not authenticated"}
        
        result = self.server.receive_messages(
            self.username,
            self.device_id,
            self.session_token
        )
        
        if result["status"] == "success" and result["messages"]:
            # Decrypt messages
            decrypted_messages = []
            for message_package in result["messages"]:
                decrypted = self.server.decrypt_message(
                    message_package["message"],
                    message_package["key"],
                    self.private_keys.get("device", "")
                )
                decrypted_messages.append(decrypted)
            
            return {
                "status": "success",
                "message": f"Received {len(decrypted_messages)} messages",
                "messages": decrypted_messages
            }
        
        return result