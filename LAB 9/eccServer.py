import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
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
    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65431))
    server_socket.listen(5)
    print("Server is listening on port 65432.")

    # Generate ECDH keys for server
    server_ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_ec_public_key = server_ec_private_key.public_key()

    # Generate RSA keys for signing
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    print("\nGenerated RSA key pair for signing.")

    while True:
        conn, addr = server_socket.accept()
        print(f"\nConnected by {addr}")

        # Receive client's public key
        client_public_bytes = b""
        while True:
            part = conn.recv(1024)
            client_public_bytes += part
            if b"-----END PUBLIC KEY-----" in client_public_bytes:
                break
        client_ec_public_key = serialization.load_pem_public_key(client_public_bytes, backend=default_backend())
        print("Received ECC public key from client.")

        # Send server's public key to client
        server_public_bytes = server_ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(server_public_bytes)
        print("Sent ECC public key to client.")

        # Perform ECDH to derive shared secret
        shared_secret = server_ec_private_key.exchange(ec.ECDH(), client_ec_public_key)
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

        # Receive payload from client
        payload = b""
        while True:
            part = conn.recv(4096)
            if not part:
                break
            payload += part
            try:
                data = pickle.loads(payload)
                break
            except:
                continue

        role = data.get('role')

        if role == 'master':
            ciphertext_hex = data.get('ciphertext')
            iv_hex = data.get('iv')
            signature_hex = data.get('signature')

            ciphertext = bytes.fromhex(ciphertext_hex)
            iv = bytes.fromhex(iv_hex)
            signature = bytes.fromhex(signature_hex)

            print(f"\nReceived encrypted hash and signature from Master.")
            print(f"Ciphertext: {ciphertext_hex}")
            print(f"IV: {iv_hex}")
            print(f"Signature: {signature_hex}")

            # Decrypt the hash
            decrypted_hash = aes_decrypt(derived_key, iv, ciphertext)
            print(f"Decrypted SHA-256 Hash: {decrypted_hash.hex()}")

            # Verify the signature using client's RSA public key
            # For demonstration, assume client has sent RSA public key
            # Here, we'll generate a temporary RSA public key
            # In practice, exchange RSA public keys securely
            # For this example, we'll skip verification as we don't have client's RSA public key
            # To properly verify, the client should send its RSA public key

            # Placeholder: Assuming signature is valid (since we don't have client's RSA public key)
            # In real implementation, verify signature here

            print("Signature verification skipped (client RSA public key not provided).")

        elif role == 'assistant':
            print("\nAssistant requested attendance.")

            # For demonstration, send attendance data
            attendance = "Attendance: 95%"
            payload_response = {
                'attendance': attendance
            }
            conn.sendall(pickle.dumps(payload_response))
            print("Sent attendance to Assistant.")

        else:
            print("Unknown role or invalid message.")

        conn.close()

if __name__ == "__main__":
    main()
