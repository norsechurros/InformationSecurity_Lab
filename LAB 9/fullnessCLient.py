import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.number import getPrime, inverse
import pickle

def diffie_hellman_client(s):
    # Generate Diffie-Hellman parameters
    p = getPrime(256)
    g = 2
    a = get_random_bytes(32)
    a = int.from_bytes(a, byteorder='big')
    A = pow(g, a, p)

    # Send p, g, and A to server
    s.sendall(pickle.dumps({'p': p, 'g': g, 'A': A}))

    # Receive B from server
    data = s.recv(4096)
    B = pickle.loads(data)['B']

    # Compute shared secret
    shared_secret = pow(B, a, p)
    print(f"Client computed shared secret: {shared_secret}")

    # Derive AES key from shared secret
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    salt = b'client_salt'  # In practice, use a secure random salt
    aes_key = PBKDF2(shared_secret_bytes, salt, dkLen=16)
    print(f"Client derived AES key: {aes_key.hex()}")

    return aes_key

def rsa_sign(message_hash):
    # Generate RSA key pair
    key = RSA.generate(1024)  # Small key size for demonstration
    private_key = key
    public_key = key.publickey()
    print("\nClient RSA Keys:")
    print(f"Private key (PEM format):\n{private_key.export_key().decode()}")
    print(f"Public key (PEM format):\n{public_key.export_key().decode()}")

    # Sign the hash
    signature = pkcs1_15.new(private_key).sign(message_hash)
    print(f"Client generated RSA signature: {signature.hex()}")

    return signature, public_key

def main():
    # Connect to server
    s = socket.socket()
    s.connect(('localhost', 12345))
    print("Client connected to server.")

    # Diffie-Hellman Key Exchange
    aes_key = diffie_hellman_client(s)

    # Prepare message
    message = "Hello, this is a test message."
    print(f"\nClient message: {message}")

    # Encrypt the message using AES
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    print(f"Client AES IV: {iv.hex()}")
    print(f"Client AES ciphertext: {ciphertext.hex()}")

    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode())
    print(f"Client SHA-256 hash: {hash_obj.hexdigest()}")

    # Sign the hash using RSA
    signature, public_key = rsa_sign(hash_obj)

    # Send data to server
    data = {
        'ciphertext': ciphertext,
        'iv': iv,
        'signature': signature,
        'public_key': public_key.export_key().decode()
    }
    s.sendall(pickle.dumps(data))
    print("Client sent encrypted message and signature to server.")

    # Receive verification result from server
    server_response = s.recv(4096)
    verification_result = pickle.loads(server_response)
    print(f"\nServer verification result: {verification_result}")

    # Demonstrate homomorphic property of RSA
    # Send two numbers to server for homomorphic encryption
    m1 = 42
    m2 = 13
    print(f"\nClient messages for homomorphic encryption: m1={m1}, m2={m2}")

    # Encrypt messages using server's public RSA key (to be obtained from server)
    # Request server's RSA public key
    s.sendall(b'get_server_rsa_key')
    server_rsa_key_data = s.recv(4096)
    server_rsa_public_key = RSA.import_key(server_rsa_key_data)
    print(f"Client received server's RSA public key.")

    # Encrypt m1 and m2
    c1 = pow(m1, server_rsa_public_key.e, server_rsa_public_key.n)
    c2 = pow(m2, server_rsa_public_key.e, server_rsa_public_key.n)
    print(f"Client encrypted c1: {c1}")
    print(f"Client encrypted c2: {c2}")

    # Send encrypted messages to server for homomorphic operation
    homomorphic_data = {
        'c1': c1,
        'c2': c2
    }
    s.sendall(pickle.dumps(homomorphic_data))
    print("Client sent encrypted messages for homomorphic operation.")

    # Receive homomorphic result from server
    homomorphic_result = s.recv(4096)
    homomorphic_result = pickle.loads(homomorphic_result)
    decrypted_result = homomorphic_result['decrypted_result']
    expected = (m1 * m2) % server_rsa_public_key.n
    print(f"Client received decrypted homomorphic result: {decrypted_result}")
    print(f"Expected result: {expected}")

    if decrypted_result == expected:
        print("Homomorphic property verified.")
    else:
        print("Homomorphic property verification failed.")

    s.close()
    print("Client disconnected.")

if __name__ == "__main__":
    main()
