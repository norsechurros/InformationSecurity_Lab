import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import logging
import threading
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class KeyManagementService:
    def __init__(self):
        self.keys = {}
        self.key_size = 2048  # Default key size
        self.renewal_interval = timedelta(days=365)  # 12 months

    def generate_keys(self, facility_name):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode()
        
        self.keys[facility_name] = {
            'public_key': public_pem,
            'private_key': private_pem,
            'last_updated': datetime.now(),
            'created_at': datetime.now()
        }
        
        logging.info(f'Keys generated for {facility_name}')
        return f'Keys generated for {facility_name}'

    def get_public_key(self, facility_name):
        if facility_name in self.keys:
            return self.keys[facility_name]['public_key']
        else:
            logging.warning(f'Facility {facility_name} not found')
            return None

    def revoke_keys(self, facility_name):
        if facility_name in self.keys:
            del self.keys[facility_name]
            logging.info(f'Keys revoked for {facility_name}')
            return f'Keys revoked for {facility_name}'
        else:
            logging.warning(f'Facility {facility_name} not found')
            return None

    def renew_keys(self, facility_name):
        if facility_name in self.keys:
            self.generate_keys(facility_name)
            logging.info(f'Keys renewed for {facility_name}')
            return f'Keys renewed for {facility_name}'
        else:
            logging.warning(f'Facility {facility_name} not found')
            return None

    def display_all_facilities(self):
        facilities = list(self.keys.keys())
        return f'Current facilities: {facilities}'

    def renew_keys_if_needed(self):
        current_time = datetime.now()
        facilities_to_renew = []

        for facility, key_info in self.keys.items():
            time_since_creation = current_time - key_info['created_at']
            if time_since_creation >= self.renewal_interval:
                facilities_to_renew.append(facility)

        for facility in facilities_to_renew:
            self.generate_keys(facility)
            logging.info(f'Keys automatically renewed for {facility}')

    def start_auto_renewal(self):
        def auto_renew():
            while True:
                self.renew_keys_if_needed()
                time.sleep(86400)  # Check daily

        threading.Thread(target=auto_renew).start()

class SecureCommunicationSystem:
    def __init__(self):
        self.roles = {}
        self.shared_secret = 109  # Simulated shared secret for simple encryption/decryption

    def add_role(self, role_name):
        self.roles[role_name] = {'public_key': None}
        print(f'Role {role_name} added.')

    def list_roles(self):
        return list(self.roles.keys())

    def encrypt_message(self, message):
        # Simple encryption: convert message characters to integers, add the shared secret
        encrypted_message = [ord(c) + self.shared_secret for c in message]
        # Convert the encrypted integers to bytes, then encode in base64
        encrypted_bytes = b''.join([chr(num).encode() for num in encrypted_message])
        encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_base64

    def decrypt_message(self, encrypted_base64):
        # Decode base64 to bytes
        encrypted_bytes = base64.b64decode(encrypted_base64)
        # Convert bytes back to integers and decrypt by subtracting the shared secret
        decrypted_message = ''.join([chr(ord(c) - self.shared_secret) for c in encrypted_bytes.decode('utf-8')])
        return decrypted_message

def main():
    kms = KeyManagementService()
    secure_comm = SecureCommunicationSystem()
    
    # Example usage of the communication system
    print("Finance is preparing to send a message...")
    message = "Secure Message from Finance"
    encrypted_message = secure_comm.encrypt_message(message)
    print(f"Encrypted message: {encrypted_message}")

    print("\nHR received an encrypted message...")
    decrypted_message = secure_comm.decrypt_message(encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

    while True:
        print("\n--- Secure Communication System ---")
        print("1. Add a new role")
        print("2. List available roles")
        print("3. Send a message between roles")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            role_name = input("Enter role name: ")
            secure_comm.add_role(role_name)
        elif choice == "2":
            roles = secure_comm.list_roles()
            print(f"Available roles: {roles}")
        elif choice == "3":
            sender = input("Enter sender role: ")
            receiver = input("Enter receiver role: ")
            message = input("Enter the message to send: ")
            encrypted_message = secure_comm.encrypt_message(message)
            print(f"Encrypted message: {encrypted_message}")
            print(f"{receiver} received an encrypted message...")
            decrypted_message = secure_comm.decrypt_message(encrypted_message)
            print(f"Decrypted message: {decrypted_message}")
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
