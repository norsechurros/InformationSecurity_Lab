import socket
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.number import inverse
import pickle

def diffie_hellman_server(conn):
    # Receive p, g, and A from client
    data = conn.recv(4096)
    params = pickle.loads(data)
    p = params['p']
    g = params['g']
    A = params['A']

    # Generate server's private key and public key
    b = get_random_bytes(32)
    b = int.from_bytes(b, byteorder='big')
    B = pow(g, b, p)

    # Send B to client
    conn.sendall(pickle.dumps({'B': B}))

    # Compute shared secret
    shared_secret = pow(A, b, p)
    print(f"Server computed shared secret: {shared_secret}")

    # Derive AES key from shared secret
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    salt = b'client_salt'  # Should use the same salt as client
    aes_key = PBKDF2(shared_secret_bytes, salt, dkLen=16)
    print(f"Server derived AES key: {aes_key.hex()}")

    return aes_key

def handle_client(conn, addr):
    print(f"\nServer connected to client at {addr}")

    # Diffie-Hellman Key Exchange
    aes_key = diffie_hellman_server(conn)

    # Receive data from client
    data = conn.recv(4096)
    data = pickle.loads(data)
    ciphertext = data['ciphertext']
    iv = data['iv']
    signature = data['signature']
    client_public_key_pem = data['public_key']

    print(f"\nServer received ciphertext: {ciphertext.hex()}")
    print(f"Server received IV: {iv.hex()}")

    # Decrypt the message using AES
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size).decode()
    print(f"Server decrypted message: {plaintext}")

    # Hash the message using SHA-256
    hash_obj = SHA256.new(plaintext.encode())
    print(f"Server SHA-256 hash: {hash_obj.hexdigest()}")

    # Load client's RSA public key
    client_public_key = RSA.import_key(client_public_key_pem)
    print("\nServer received client's RSA public key.")

    # Verify the signature
    try:
        pkcs1_15.new(client_public_key).verify(hash_obj, signature)
        verification_result = "Signature verification successful."
        print("Server signature verification successful.")
    except (ValueError, TypeError):
        verification_result = "Signature verification failed."
        print("Server signature verification failed.")

    # Send verification result back to client
    conn.sendall(pickle.dumps(verification_result))

    # Check for homomorphic operation request
    data = conn.recv(4096)
    if data == b'get_server_rsa_key':
        # Send server's RSA public key
        server_rsa_key = RSA.generate(1024)  # Small key size for demonstration
        server_rsa_public_key = server_rsa_key.publickey()
        conn.sendall(server_rsa_public_key.export_key())
        print("\nServer sent RSA public key to client for homomorphic operation.")

        # Receive encrypted messages from client
        data = conn.recv(4096)
        homomorphic_data = pickle.loads(data)
        c1 = homomorphic_data['c1']
        c2 = homomorphic_data['c2']
        print(f"Server received c1: {c1}")
        print(f"Server received c2: {c2}")

        # Perform homomorphic operation
        n = server_rsa_public_key.n
        c_mul = (c1 * c2) % n
        print(f"Server computed c1 * c2 mod n: {c_mul}")

        # Decrypt the result
        decrypted_result = pow(c_mul, server_rsa_key.d, n)
        print(f"Server decrypted homomorphic result: {decrypted_result}")

        # Send decrypted result back to client
        conn.sendall(pickle.dumps({'decrypted_result': decrypted_result}))

    conn.close()
    print("Server connection closed.")

def main():
    # Start server
    server_socket = socket.socket()
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Server is listening on port 12345.")

    while True:
        conn, addr = server_socket.accept()
        client_thread = Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

if __name__ == "__main__":
    main()
