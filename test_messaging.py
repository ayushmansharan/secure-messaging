from server import SecureMessagingSystem
from client import SecureMessagingClient


def test_secure_messaging_system():
    # Initialize server
    server = SecureMessagingSystem()
    
    # Create users
    alice_client = SecureMessagingClient(server, "alice", "alice_phone_1")
    bob_client = SecureMessagingClient(server, "bob", "bob_phone_1")
    
    # Register accounts
    print("Registering Alice...")
    print(alice_client.register_account("alice_secure_password"))
    
    print("Registering Bob...")
    print(bob_client.register_account("bob_secure_password"))
    
    # Login
    print("Alice logging in...")
    print(alice_client.login("alice_secure_password"))
    
    print("Bob logging in...")
    print(bob_client.login("bob_secure_password"))
    
    # Register devices
    print("Registering Alice's device...")
    print(alice_client.register_device("Alice's iPhone"))
    
    print("Registering Bob's device...")
    print(bob_client.register_device("Bob's Android"))
    
    # Send messages
    print("Alice sending message to Bob...")
    print(alice_client.send_message("bob", "bob_phone_1", "Hello Bob! This is a secure message."))
    
    print("Bob checking messages...")
    print(bob_client.check_messages())
    
    print("Bob replying to Alice...")
    print(bob_client.send_message("alice", "alice_phone_1", "Hi Alice! Got your message securely."))
    
    print("Alice checking messages...")
    print(alice_client.check_messages())


if __name__ == "__main__":
    test_secure_messaging_system()