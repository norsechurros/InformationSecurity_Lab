import os
import logging
from datetime import datetime, timedelta
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ElGamalKeyPair:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """Generate ElGamal public-private key pair."""
        self.private_key = ElGamal.generate(256, os.urandom)
        self.public_key = self.private_key.publickey()
        logging.info("ElGamal keys generated successfully.")

    def get_public_key_str(self):
        """Return public key as a string."""
        return f"y: {self.public_key.y}, p: {self.public_key.p}, g: {self.public_key.g}"

class DRMService:
    def __init__(self):
        self.content_store = {}  # Store content as a dictionary
        self.access_control = []  # List to manage access control
        self.key_pair = ElGamalKeyPair()

    def encrypt_content(self, title, content):
        """Encrypt the digital content using ElGamal encryption."""
        # Ensure the keys are generated before encrypting content
        if self.key_pair.public_key is None:
            logging.error("ElGamal keys must be generated before encrypting content.")
            return None

        # Generate a random AES key for content encryption
        aes_key = get_random_bytes(16)  # AES-128
        cipher = AES.new(aes_key, AES.MODE_CBC)

        # Pad and encrypt the content using AES
        ct_bytes = cipher.encrypt(pad(content.encode(), AES.block_size))
        iv = cipher.iv  # Initialization vector
        encrypted_content = iv + ct_bytes  # Prepend IV to ciphertext

        # Encrypt the AES key using ElGamal
        aes_key_ciphertext = self.encrypt_aes_key(aes_key)

        content_id = len(self.content_store) + 1  # Simple auto-incrementing ID
        self.content_store[content_id] = {
            'title': title,
            'encrypted_content': encrypted_content,
            'aes_key_ciphertext': aes_key_ciphertext
        }

        logging.info(f"Content '{title}' encrypted and stored with ID {content_id}.")
        return content_id

    def encrypt_aes_key(self, aes_key):
        """Encrypt the AES key using ElGamal manually."""
        k = number.getRandomRange(1, self.key_pair.public_key.p - 1)  # Random ephemeral key for ElGamal
        c1 = pow(self.key_pair.public_key.g, k, self.key_pair.public_key.p)  # g^k mod p
        c2 = (int.from_bytes(aes_key, byteorder='big') * pow(self.key_pair.public_key.y, k, self.key_pair.public_key.p)) % self.key_pair.public_key.p  # m * y^k mod p
        return (c1, c2)

    def decrypt_content(self, content_id, customer_email):
        """Decrypt the content if access is granted."""
        if self.has_access(content_id, customer_email):
            content = self.content_store[content_id]
            aes_key = self.decrypt_aes_key(content['aes_key_ciphertext'])

            iv = content['encrypted_content'][:AES.block_size]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)

            decrypted_content = unpad(cipher.decrypt(content['encrypted_content'][AES.block_size:]), AES.block_size)
            return decrypted_content.decode()
        else:
            logging.warning(f"Access denied for {customer_email} to content ID {content_id}.")
            return None

    def decrypt_aes_key(self, aes_key_ciphertext):
        """Decrypt the AES key using ElGamal private key."""
        c1, c2 = aes_key_ciphertext
        # Calculate shared secret: s = c1^x mod p, where x is the private key
        s = pow(c1, self.key_pair.private_key.x, self.key_pair.public_key.p)
        # Compute the multiplicative inverse of s
        s_inv = pow(s, -1, self.key_pair.public_key.p)
        # Recover the AES key
        decrypted_aes_key_int = (c2 * s_inv) % self.key_pair.public_key.p
        return decrypted_aes_key_int.to_bytes(16, byteorder='big')  # Convert back to bytes

    def grant_access(self, content_id, customer_email, duration_days):
        """Grant limited-time access to customers for specific content."""
        expiration_date = datetime.now() + timedelta(days=duration_days)

        self.access_control.append({
            'content_id': content_id,
            'customer_email': customer_email,
            'expiration_date': expiration_date
        })
        logging.info(f"Granted access to {customer_email} for content ID {content_id} until {expiration_date}.")

    def revoke_access(self, content_id, customer_email):
        """Revoke access to customers for specific content."""
        self.access_control = [
            access for access in self.access_control
            if not (access['content_id'] == content_id and access['customer_email'] == customer_email)
        ]
        logging.info(f"Revoked access to {customer_email} for content ID {content_id}.")

    def has_access(self, content_id, customer_email):
        """Check if a customer has access to a specific content."""
        for access in self.access_control:
            if (access['content_id'] == content_id and 
                access['customer_email'] == customer_email and 
                access['expiration_date'] > datetime.now()):
                return True
        return False

    def display_content(self):
        """Display all encrypted content."""
        for content_id, content in self.content_store.items():
            print(f"Content ID: {content_id}, Title: {content['title']}, Encrypted Content (Hex): {content['encrypted_content'].hex()}")

def main_menu():
    drm_service = DRMService()

    while True:
        print("\n--- DRM Service Menu ---")
        print("1. Generate ElGamal Keys")
        print("2. Encrypt Content")
        print("3. Grant Access")
        print("4. Revoke Access")
        print("5. Display Encrypted Content")
        print("6. Decrypt Content")
        print("7. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            drm_service.key_pair.generate_keys()
            print(f"Public Key: {drm_service.key_pair.get_public_key_str()}")

        elif choice == '2':
            title = input("Enter content title: ")
            content = input("Enter content to encrypt: ")
            content_id = drm_service.encrypt_content(title, content)
            if content_id:
                print(f"Content ID: {content_id}")

        elif choice == '3':
            content_id = int(input("Enter content ID to grant access: "))
            customer_email = input("Enter customer email: ")
            duration_days = int(input("Enter duration in days: "))
            drm_service.grant_access(content_id, customer_email, duration_days)

        elif choice == '4':
            content_id = int(input("Enter content ID to revoke access: "))
            customer_email = input("Enter customer email: ")
            drm_service.revoke_access(content_id, customer_email)

        elif choice == '5':
            drm_service.display_content()

        elif choice == '6':
            content_id = int(input("Enter content ID to decrypt: "))
            customer_email = input("Enter your email: ")
            decrypted_content = drm_service.decrypt_content(content_id, customer_email)
            if decrypted_content:
                print(f"Decrypted Content: {decrypted_content}")
            else:
                print("Access denied or content not found.")

        elif choice == '7':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
