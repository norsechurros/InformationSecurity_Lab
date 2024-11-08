import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

def generate_rsa_keys():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Small key size for demonstration; use >=2048 in production
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def aes_encrypt(key, plaintext):
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    # Create AES Cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad plaintext to be multiple of block size (16 bytes)
    pad_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    # Create AES Cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove padding
    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len]
    return plaintext

def main():
    # Establish connection to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65431))
    print("Connected to server.")

    # Generate ECDH keys
    client_ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_ec_public_key = client_ec_private_key.public_key()

    # Send client's public key to server
    client_public_bytes = client_ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(client_public_bytes)
    print("Sent ECC public key to server.")

    # Receive server's public key
    server_public_bytes = b""
    while True:
        part = client_socket.recv(1024)
        server_public_bytes += part
        if b"-----END PUBLIC KEY-----" in server_public_bytes:
            break
    server_ec_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())
    print("Received ECC public key from server.")

    # Perform ECDH to derive shared secret
    shared_secret = client_ec_private_key.exchange(ec.ECDH(), server_ec_public_key)
    print(f"Derived shared secret: {shared_secret.hex()}")

    # Derive AES key from shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    print(f"Derived AES key: {derived_key.hex()}")

    # Generate RSA keys for signing
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    print("\nGenerated RSA key pair for signing.")

    # Choose role
    while True:
        print("\nSelect Role:")
        print("1. Master")
        print("2. Assistant")
        print("3. Exit")
        choice = input("Enter choice: ")

        if choice == '1':
            role = 'master'
            name = input("Enter your name: ")
            marks = input("Enter marks: ")
            attendance = input("Enter attendance: ")

            # Prepare data
            data = f"{name},{marks},{attendance}".encode()
            print(f"\nOriginal Data: {data}")

            # Hash the data using SHA-256
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data)
            data_hash = digest.finalize()
            print(f"SHA-256 Hash: {data_hash.hex()}")

            # Encrypt the hash using AES
            iv, ciphertext = aes_encrypt(derived_key, data_hash)
            print(f"AES Encrypted Hash (IV): {iv.hex()}")
            print(f"AES Encrypted Hash (Ciphertext): {ciphertext.hex()}")

            # Sign the hash using RSA
            signature = rsa_private_key.sign(
                data_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"RSA Signature: {signature.hex()}")

            # Prepare payload
            payload = {
                'role': role,
                'ciphertext': ciphertext.hex(),
                'iv': iv.hex(),
                'signature': signature.hex()
            }

            # Send payload to server
            client_socket.sendall(pickle.dumps(payload))
            print("Sent encrypted hash and signature to server.")

        elif choice == '2':
            role = 'assistant'
            print("\nAssistant can view attendance only.")

            # Prepare payload
            payload = {
                'role': role
            }

            # Send payload to server
            client_socket.sendall(pickle.dumps(payload))
            print("Requested attendance from server.")

            # Receive response
            response = b""
            while True:
                part = client_socket.recv(4096)
                if not part:
                    break
                response += part
                try:
                    data = pickle.loads(response)
                    break
                except:
                    continue

            if 'attendance' in data:
                print(f"Attendance: {data['attendance']}")
            if 'error' in data:
                print(f"Error: {data['error']}")

        elif choice == '3':
            print("Exiting.")
            client_socket.close()
            break
        else:
            print("Invalid choice. Please try again.")

    # Demonstrate RSA Homomorphic Property
    print("\n--- Demonstrating RSA Homomorphic Property ---")
    m1 = 5
    m2 = 7
    print(f"Original messages: m1 = {m1}, m2 = {m2}")

    # Encrypt messages using server's RSA public key
    # For demonstration, assume server has an RSA public key
    # Here, we'll generate a temporary RSA key pair
    temp_rsa_private_key, temp_rsa_public_key = generate_rsa_keys()

    c1 = temp_rsa_public_key.encrypt(
        m1.to_bytes((m1.bit_length() + 7) // 8, byteorder='big'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    c2 = temp_rsa_public_key.encrypt(
        m2.to_bytes((m2.bit_length() + 7) // 8, byteorder='big'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Encrypted messages: c1 = {c1.hex()}, c2 = {c2.hex()}")

    # Homomorphic property: c1 * c2 mod n = E(m1 * m2 mod n)
    n = temp_rsa_public_key.public_numbers().n
    c_mul = (int.from_bytes(c1, byteorder='big') * int.from_bytes(c2, byteorder='big')) % n
    print(f"c1 * c2 mod n = {c_mul}")

    # Decrypt the result
    decrypted_mul = temp_rsa_private_key.decrypt(
        c_mul.to_bytes((c_mul.bit_length() + 7) // 8, byteorder='big'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted_mul_int = int.from_bytes(decrypted_mul, byteorder='big')
    print(f"Decrypted c1 * c2 mod n = {decrypted_mul_int}")

    # Expected result
    expected = (m1 * m2) % n
    print(f"Expected m1 * m2 mod n = {expected}")

    if decrypted_mul_int == expected:
        print("Homomorphic property verified.")
    else:
        print("Homomorphic property verification failed.")

if __name__ == "__main__":
    main()
