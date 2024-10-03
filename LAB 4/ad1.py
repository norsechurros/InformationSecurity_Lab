import logging
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class DRMService:
    def __init__(self):
        self.master_private_key = None
        self.master_public_key = None
        self.content_store = {}  # Store content as a dictionary
        self.access_control = []  # List to manage access control
        self.audit_log = []  # List for auditing actions

    def generate_keys(self, key_size=2048):
        """Generate a master public-private key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Store the keys
        self.master_private_key = private_key
        self.master_public_key = public_key

        logging.info("Keys generated successfully.")
        return self.master_public_key, self.master_private_key

    def encrypt_content(self, title, content, owner):
        """Encrypt the digital content and store it in memory."""
        if self.master_public_key is None:
            logging.error("Master public key is not generated.")
            return None

        # Encrypt the content using the public key
        encrypted_content = self.master_public_key.encrypt(
            content.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        content_id = len(self.content_store) + 1  # Simple auto-incrementing ID
        self.content_store[content_id] = {
            'title': title,
            'encrypted_content': encrypted_content,
            'owner': owner
        }

        logging.info(f"Content '{title}' encrypted and stored with ID {content_id}.")
        return content_id

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

    def list_content(self):
        """List all content in memory."""
        return self.content_store

    def decrypt_content(self, content_id, customer_email):
        """Decrypt content for a customer."""
        if content_id not in self.content_store:
            logging.error("Content not found.")
            return None

        encrypted_content = self.content_store[content_id]['encrypted_content']

        # Check if the customer has access
        if not self.has_access(content_id, customer_email):
            logging.error("Customer does not have access to this content.")
            return None

        try:
            # Decrypt the content using the private key
            decrypted_content = self.master_private_key.decrypt(
                encrypted_content,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logging.info(f"Decrypted content for customer {customer_email}.")
            return decrypted_content.decode()
        except Exception as e:
            logging.error(f"An error occurred while decrypting the content: {str(e)}")
            return None

    def has_access(self, content_id, customer_email):
        """Check if a customer has access to a specific content."""
        for access in self.access_control:
            if (access['content_id'] == content_id and 
                access['customer_email'] == customer_email and 
                access['expiration_date'] > datetime.now()):
                return True
        return False

    def revoke_master_key(self):
        """Revoke the master private key."""
        self.master_private_key = None
        logging.info("Master private key revoked.")

    def renew_keys(self):
        """Renew the master public-private key pair."""
        self.generate_keys()
        logging.info("Master keys renewed.")

    def audit_log_action(self, action):
        """Log actions for auditing."""
        self.audit_log.append({
            'action': action,
            'timestamp': datetime.now()
        })
        logging.info(f"Logged action: {action}")


# Example Usage
if __name__ == "__main__":
    drm_service = DRMService()
    drm_service.generate_keys()

    # Encrypting content
    content_id = drm_service.encrypt_content("E-Book Title", "This is the content of the e-book.", "Alice")

    # Granting access
    drm_service.grant_access(content_id, "bob@example.com", 30)  # Content ID 1, Bob gets access for 30 days

    # Listing content
    content_list = drm_service.list_content()
    print(content_list)

    # Decrypting content
    decrypted_content = drm_service.decrypt_content(content_id, "bob@example.com")
    print(f"Decrypted Content: {decrypted_content}")

    # Revoking access
    drm_service.revoke_access(content_id, "bob@example.com")
