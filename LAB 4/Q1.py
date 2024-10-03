import random
import math

# Function to check if a number is prime
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

# Generate a random small prime number
def generate_small_prime():
    while True:
        num = random.randint(100, 300)  # Smaller prime range for testing
        if is_prime(num):
            return num

# Modular exponentiation function (more efficient)
def mod_exp(base, exp, modulus):
    result = 1
    base = base % modulus
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % modulus
        exp >>= 1
        base = (base * base) % modulus
    return result

# RSA Encryption and Decryption
class RSA:
    def __init__(self):
        self.p = generate_small_prime()
        self.q = generate_small_prime()
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        
        # Find e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
        self.e = random.randrange(3, self.phi // 2)  # Start from a smaller number
        while math.gcd(self.e, self.phi) != 1:
            self.e += 1
        
        # Compute d such that d*e = 1 (mod phi(n))
        self.d = pow(self.e, -1, self.phi)

    def encrypt(self, plaintext):
        encrypted_blocks = [pow(ord(char), self.e, self.n) for char in plaintext]
        return encrypted_blocks

    def decrypt(self, ciphertext):
        decrypted_message = [chr(mod_exp(block, self.d, self.n)) for block in ciphertext]
        return ''.join(decrypted_message)

# Diffie-Hellman Key Exchange
class DiffieHellman:
    def __init__(self):
        self.p = generate_small_prime()  # Prime modulus
        self.g = random.randrange(2, self.p)  # Base

    def generate_keys(self):
        self.private_key = random.randrange(1, self.p)
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key

    def compute_shared_secret(self, peer_public_key):
        return mod_exp(peer_public_key, self.private_key, self.p)

# Role class
class Role:
    def __init__(self, name):
        self.name = name
        self.rsa = RSA()
        self.diffie_hellman = DiffieHellman()

    def send_message(self, destination_role, message):
        print(f"\n{self.name} is preparing to send a message...")

        # Perform Diffie-Hellman key exchange
        self_diffie_hellman_public_key = self.diffie_hellman.generate_keys()
        destination_diffie_hellman_public_key = destination_role.diffie_hellman.generate_keys()

        shared_secret = self.diffie_hellman.compute_shared_secret(destination_diffie_hellman_public_key)
        print(f"{self.name}'s shared secret: {shared_secret}")

        # Encrypt the message using RSA
        encrypted_message = self.rsa.encrypt(message)
        print(f"Encrypted message: {' '.join(map(str, encrypted_message))}")

        # Send the encrypted message to the destination role
        destination_role.receive_message(encrypted_message, shared_secret)

    def receive_message(self, encrypted_message, shared_secret):
        print(f"\n{self.name} received an encrypted message...")

        # Decrypt the message using RSA
        decrypted_message = self.rsa.decrypt(encrypted_message)
        print(f"Decrypted message: {decrypted_message}")

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
