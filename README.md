🔐 Secure Messaging System with User Authentication
This project implements a secure end-to-end messaging system that features robust user authentication, device registration, and encrypted communication between users using modern cryptographic algorithms. It simulates both server-side logic and client-side behavior in a single Python module.

🚀 Features
✅ User Registration with Salted Password Hashing (using SHA256 as a placeholder for Argon2id)

✅ Secure Device Registration (X25519 key pairs)

✅ Session-based Authentication (Token-based)

✅ End-to-End Encrypted Messaging (ChaCha20-Poly1305)

✅ Message Compression (Brotli)

✅ Per-Device Message Queueing and Retrieval

✅ Message Decryption (Client-side simulation)

✅ Account Lockout on Multiple Failed Attempts

🧠 Tech Stack & Cryptographic Primitives
Ed25519: Identity key pair for signing

X25519: Ephemeral key exchange for secure device communication

ChaCha20Poly1305: AEAD encryption for fast and secure message delivery

HMAC & SHA256: Secure password validation (SHA256 used as placeholder for Argon2id)

Brotli: Compression for message content

Secrets: Cryptographically secure random token generation

🧪 Components
📡 Server - SecureMessagingSystem
Handles:

User and device registration

Authentication and session token issuance

Secure channel initiation

Encrypted message sending

Message queuing and retrieval

Decryption (for simulation/testing only)

💻 Client - SecureMessagingClient
Simulates:

Registering an account and a device

Logging in with session token management

Establishing secure channels with contacts

Sending and receiving encrypted messages

📦 Example Usage
python
Copy
Edit
# Initialize server
server = SecureMessagingSystem()

# Create clients
alice = SecureMessagingClient(server, "alice", "alice_phone_1")
bob = SecureMessagingClient(server, "bob", "bob_phone_1")

# Register users
alice.register_account("alice_secure_password")
bob.register_account("bob_secure_password")

# Authenticate users
alice.login("alice_secure_password")
bob.login("bob_secure_password")

# Register devices (if needed)
alice.register_device("Alice's Phone")
bob.register_device("Bob's Phone")

# Establish channel and send message
alice.establish_secure_channel("bob", "bob_phone_1")
alice.send_message("bob", "bob_phone_1", "Hey Bob! Secure message incoming.")

# Bob checks messages
bob_messages = bob.check_messages()
print(bob_messages)
🔐 Security Notes
🔒 Password hashing uses SHA256 only for demonstration. In production, use argon2id via argon2-cffi or similar libraries.

🔒 This system does not implement a full Double Ratchet protocol (like Signal) but provides a simplified, secure approach to key exchange and message encryption.

🔒 Private keys are simulated to be stored securely — in practice, these should be stored in secure enclaves or device keychains.

📁 File Structure
plaintext
Copy
Edit
secure_messaging.py   # Full implementation including server and client classes
README.md             # You're reading it!
🛠️ Dependencies
cryptography

brotli

Install them using pip:

bash
Copy
Edit
pip install cryptography brotli
📌 To Do / Possible Improvements
 Replace SHA256 with Argon2id for password hashing

 Add proper key exchange using X3DH or Double Ratchet (for full end-to-end encryption)

 Add group messaging support

 Implement message delivery receipts

 Persist users/messages to a database

👨‍💻 Author
Developed by Ayushman Sharan as a demonstration of secure messaging principles.

📝 License
This project is licensed under the MIT License. See LICENSE file for details.
