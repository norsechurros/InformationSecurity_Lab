import socket
from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Random import random
from hashlib import sha256
import pickle

def generate_elgamal_keys(bits):
    # Generate prime p and generator g
    p = getPrime(bits)
    while True:
        g = random.randint(2, p - 1)
        if pow(g, (p - 1) // 2, p) != 1:
            break
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, g, y, x)

def elgamal_sign(m_hash_int, p, g, x):
    while True:
        k = random.randint(1, p - 2)
        if GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)
    s = (k_inv * (m_hash_int - x * r)) % (p - 1)
    return (r, s)

def rabin_encrypt(m, n):
    c = pow(m, 2, n)
    return c

def get_rabin_public_key():
    # Connect to server to get Rabin public key n
    s = socket.socket()
    s.connect(('localhost', 12345))
    s.sendall(b'get_rabin_public_key')
    n_data = s.recv(4096)
    s.close()
    n = int(n_data.decode())
    return n

def main():
    # Generate ElGamal keys
    p_elgamal_bits = 256  # Small size for demonstration
    p_elgamal, g_elgamal, y_elgamal, x_elgamal = generate_elgamal_keys(p_elgamal_bits)
    print(f"\nElGamal public key (p, g, y):\n p = {p_elgamal}\n g = {g_elgamal}\n y = {y_elgamal}")
    print(f"ElGamal private key x: {x_elgamal}")

    # Get Rabin public key from server
    n = get_rabin_public_key()
    print(f"\nReceived Rabin public key (n): {n}")

    while True:
        print("\nMenu:")
        print("1. Enter Name and Marks")
        print("2. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            # Input name and marks
            name = input("\nEnter your name: ")
            marks_input = input("Enter your marks (integer between 0 and 100): ")
            try:
                marks = int(marks_input)
                if not (0 <= marks <= 100):
                    print("Marks must be between 0 and 100.")
                    continue
            except ValueError:
                print("Invalid input. Please enter an integer between 0 and 100.")
                continue

            message = str(marks)
            # Hash the marks
            hash_obj = sha256(message.encode())
            m_hash = hash_obj.hexdigest()
            print(f"\nSHA-256 hash of marks: {m_hash}")
            m_hash_int = int(m_hash, 16)

            # Encrypt marks using Rabin encryption
            if marks >= n:
                print("Marks too large for encryption.")
                continue
            ciphertext = rabin_encrypt(marks, n)
            print(f"\nEncrypted marks (ciphertext): {ciphertext}")

            # Sign the hash using ElGamal signature
            signature = elgamal_sign(m_hash_int, p_elgamal, g_elgamal, x_elgamal)
            print(f"\nElGamal signature (r, s): {signature}")

            # Prepare data to send
            data = {
                'name': name,
                'ciphertext': ciphertext,
                'hash': m_hash,
                'signature': signature,
                'elgamal_public_key': (p_elgamal, g_elgamal, y_elgamal)
            }

            # Connect to server and send data
            s = socket.socket()
            s.connect(('localhost', 12345))
            s.sendall(pickle.dumps(data))
            s.close()
            print("\nData sent to server.")
        elif choice == '2':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
