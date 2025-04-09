# Secure Messaging System with User Authentication

## Overview
This project implements a secure messaging system that provides:

- **User authentication** using salted password hashing (simulated Argon2id)
- **Device registration** with X25519 key pairs
- **Session management** with session tokens
- **End-to-end encrypted messaging** using ChaCha20-Poly1305 and simulated key exchange
- **Message compression** using Brotli

The system is built in Python and consists of a server-side simulation class (`SecureMessagingSystem`) and a client-side interface (`SecureMessagingClient`).

---

## Features

### User Registration and Authentication
- New users can register with a username, password, and device ID.
- Passwords are hashed with salt using SHA256 as a placeholder for Argon2id.
- Login creates a session token with 24-hour expiry.
- Account lockout after 5 failed attempts.

### Device Registration
- Devices are uniquely identified and can be registered per user.
- Each device has an X25519 key pair for secure communication.

### Session Management
- Sessions are validated before any secure action.
- Session tokens are stored with creation, expiry, and last active time.

### Secure Messaging
- Messages are encrypted with ChaCha20-Poly1305 using randomly generated keys.
- Messages are compressed using Brotli before encryption.
- Each message is accompanied by a unique ID and metadata.

### Secure Channels
- Secure channels simulate key exchanges and are uniquely identified by a channel ID.

---

## How It Works

### Client Workflow
1. Register account with username, password, and device.
2. Login to obtain a session token.
3. Register the device with a name.
4. Establish a secure channel with a recipient.
5. Send and receive encrypted messages.
6. Decrypt received messages on the client side.

### Server Workflow
- Maintains users, devices, sessions, and message queues.
- Handles message encryption, delivery, and session validation.

---

## Requirements
- Python 3.6+
- `cryptography` library
- `brotli` compression library

Install dependencies using:
```bash
pip install cryptography brotli
```

---

## Example Usage
```python
server = SecureMessagingSystem()
alice = SecureMessagingClient(server, "alice", "alice_device")
bob = SecureMessagingClient(server, "bob", "bob_device")

alice.register_account("alice_password")
bob.register_account("bob_password")

alice.login("alice_password")
bob.login("bob_password")

alice.register_device("Alice's Phone")
bob.register_device("Bob's Phone")

alice.establish_secure_channel("bob", "bob_device")
alice.send_message("bob", "bob_device", "Hello Bob!")

received = bob.check_messages()
print(received)
```

---

## Limitations
- Argon2id is simulated using SHA256; not suitable for production.
- Key exchange and session key derivation are simplified.
- No persistent storage or actual networking is implemented.

---

## Future Improvements
- Use actual Argon2id for password hashing.
- Implement Double Ratchet Algorithm for perfect forward secrecy.
- Add persistent storage (e.g., database).
- Build a RESTful API or socket interface for real-time messaging.
- Add UI/UX layer for usability.

---

## License
This project is provided for educational purposes and is not intended for production use. Modify and use at your own discretion.
