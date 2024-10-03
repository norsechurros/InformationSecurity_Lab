from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import binascii
import random
import math

# Diffie-Hellman Key Exchange Class
class DiffieHellman:
    def __init__(self):
        self.p = self.generate_large_prime()  # Large prime modulus
        self.g = random.randrange(2, self.p)  # Base

    def generate_large_prime(self):
        while True:
            num = random.randint(100, 300)  # Smaller range for primes
            if self.is_prime(num):
                return num

    def is_prime(self, num):
        if num < 2:
            return False
        for i in range(2, int(math.sqrt(num)) + 1):
            if num % i == 0:
                return False
        return True

    def generate_keys(self):
        self.private_key = random.randrange(1, self.p)
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key

    def compute_shared_secret(self, peer_public_key):
        return pow(peer_public_key, self.private_key, self.p)

# Role class
class Role:
    def __init__(self, name):
        self.name = name
        self.rsa = RSA.generate(1024)  # Generate RSA keys (1024-bit for smaller size)
        self.private_key = self.rsa
        self.public_key = self.rsa.publickey()
        self.diffie_hellman = DiffieHellman()

    def send_message(self, destination_role, message):
        print(f"\n{self.name} is preparing to send a message...")

        # Perform Diffie-Hellman key exchange
        self_dh_public_key = self.diffie_hellman.generate_keys()
        destination_dh_public_key = destination_role.diffie_hellman.generate_keys()
        shared_secret = self.diffie_hellman.compute_shared_secret(destination_dh_public_key)
        print(f"{self.name}'s shared secret: {shared_secret}")

        # Encrypt the message using RSA
        cipher_rsa = PKCS1_OAEP.new(destination_role.public_key)
        encrypted_message = cipher_rsa.encrypt(message.encode())
        encrypted_message_hex = binascii.hexlify(encrypted_message).decode()
        print(f"Encrypted message: {encrypted_message_hex}")

        # Send the encrypted message and the DH public key to the destination role
        destination_role.receive_message(encrypted_message_hex, self_dh_public_key)

    def receive_message(self, encrypted_message_hex, sender_dh_public_key):
        print(f"\n{self.name} received an encrypted message...")

        # Compute shared secret using the sender's DH public key
        shared_secret = self.diffie_hellman.compute_shared_secret(sender_dh_public_key)
        print(f"{self.name}'s shared secret: {shared_secret}")

        try:
            # Convert back from hex
            encrypted_message = binascii.unhexlify(encrypted_message_hex)

            # Decrypt the message using RSA
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            decrypted_message = cipher_rsa.decrypt(encrypted_message).decode()

            print(f"Decrypted message: {decrypted_message}")

        except Exception as e:
            print(f"An error occurred while decrypting the message: {str(e)}")
            print("Failed to decrypt the message.")

# Function to create new roles
def add_role(roles):
    role_name = input("Enter the name of the new role: ")
    if role_name not in roles:
        roles[role_name] = Role(role_name)
        print(f"Role '{role_name}' added successfully.")
    else:
        print(f"A role named '{role_name}' already exists.")

# Function to list available roles
def list_roles(roles):
    print("\nAvailable roles:")
    for index, role_name in enumerate(roles.keys(), start=1):
        print(f"{index}. {role_name}")

# Main function
def main():
    roles = {
        "Finance": Role("Finance"),
        "HR": Role("HR"),
        "Supply Chain Management": Role("Supply Chain Management")
    }

    while True:
        print("\n--- Secure Communication System ---")
        print("1. Add a new role")
        print("2. List available roles")
        print("3. Send a message between roles")
        print("4. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            add_role(roles)
        elif choice == "2":
            list_roles(roles)
        elif choice == "3":
            list_roles(roles)
            
            try:
                sender_choice = int(input("\nEnter the number of the sender role: "))
                destination_choice = int(input("Enter the number of the destination role: "))

                sender_role_name = list(roles.keys())[sender_choice - 1]
                destination_role_name = list(roles.keys())[destination_choice - 1]

                message = input("Enter the message to be sent: ")

                sender_role = roles.get(sender_role_name)
                destination_role = roles.get(destination_role_name)

                if sender_role and destination_role:
                    sender_role.send_message(destination_role, message)
                else:
                    print("Invalid role selection.")
            except (ValueError, IndexError):
                print("Invalid input. Please enter valid numbers.")

        elif choice == "4":
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice. Please choose a valid option.")

if __name__ == "__main__":
    main()
