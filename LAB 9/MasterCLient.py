import socket
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Random import random, get_random_bytes
from Crypto.Util.number import getPrime
from Crypto.Math.Numbers import Integer
import pickle

def diffie_hellman_key_exchange(client_socket):
    # Generate Diffie-Hellman parameters
    p = getPrime(256)
    g = 2
    a = random.randint(1, p - 1)  # Client's private key
    A = pow(g, a, p)  # Client's public key

    # Send A to server
    dh_params = {'A': A}
    client_socket.sendall(pickle.dumps(dh_params))

    # Receive B, p, g from server
    data = client_socket.recv(4096)
    server_response = pickle.loads(data)
    B = server_response['B']
    p = server_response['p']
    g = server_response['g']

    # Compute shared secret
    shared_secret = pow(B, a, p)
    print(f"Client computed shared secret: {shared_secret}")
    return shared_secret

def main():
    # Connect to server to get public keys
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12346))

    # Request server's public keys
    client_socket.sendall(b'get_public_keys')

    # Receive server's public keys
    data = client_socket.recv(4096)
    server_keys = pickle.loads(data)
    server_rsa_public_key = RSA.import_key(server_keys['rsa_public_key'])
    elgamal_components = server_keys['elgamal_public_key']

    # Reconstruct server's ElGamal public key
    from Crypto.PublicKey import ElGamal
    from Crypto.Math.Numbers import Integer

    server_elgamal_public_key = ElGamal.construct((
        Integer(elgamal_components['p']),
        Integer(elgamal_components['g']),
        Integer(elgamal_components['y'])
    ))

    print("\nReceived and reconstructed server's RSA and ElGamal public keys.")

    # Generate client's ElGamal key pair for signing using get_random_bytes
    client_elgamal_key = ElGamal.generate(256, get_random_bytes)
    client_elgamal_public_key = client_elgamal_key.publickey()
    print("Generated client's ElGamal key pair.")

    # Send client's ElGamal public key to server
    client_elgamal_public_key_components = {
        'p': int(client_elgamal_public_key.p),
        'g': int(client_elgamal_public_key.g),
        'y': int(client_elgamal_public_key.y)
    }
    message = {'client_elgamal_public_key': client_elgamal_public_key_components}
    client_socket.sendall(pickle.dumps(message))

    # Perform Diffie-Hellman key exchange
    shared_secret = diffie_hellman_key_exchange(client_socket)
    client_socket.close()

    while True:
        print("\nSelect your role:")
        print("1. Master")
        print("2. Assistant")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            # Master role
            # Input marks and attendance
            marks = input("Enter marks: ")
            attendance = input("Enter attendance: ")

            # Hash the data
            data = f"{marks},{attendance}"
            hash_obj = SHA256.new(data.encode())
            hash_hex = hash_obj.hexdigest()
            print(f"\nSHA256 Hash of data: {hash_hex}")

            # Encrypt the data using server's RSA public key
            cipher_rsa = PKCS1_OAEP.new(server_rsa_public_key)
            ciphertext = cipher_rsa.encrypt(data.encode())
            print(f"\nEncrypted data (ciphertext): {ciphertext.hex()}")

            # Sign the hash using client's ElGamal private key
            signer = DSS.new(client_elgamal_key, 'fips-186-3')
            signature = signer.sign(hash_obj)
            print(f"\nElGamal Signature: {signature.hex()}")

            # Send data to server
            message = {
                'role': 'master',
                'ciphertext': ciphertext,
                'signature': signature,
                'hash_hex': hash_hex
            }

            # Connect to server and send data
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('localhost', 12346))
            client_socket.sendall(pickle.dumps(message))
            client_socket.close()
            print("Data sent to server.")

        elif choice == '2':
            # Assistant role
            # Request attendance from server
            message = {'role': 'assistant', 'request': 'get_attendance'}

            # Connect to server and send request
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('localhost', 12346))
            client_socket.sendall(pickle.dumps(message))

            # Receive response
            data = client_socket.recv(4096)
            response = pickle.loads(data)
            client_socket.close()

            if response.get('error'):
                print(f"Error: {response['error']}")
            else:
                # Assistant can see attendance
                attendance = response.get('attendance')
                print(f"\nAttendance: {attendance}")

                # Attempt to view marks (should fail)
                marks_encrypted = response.get('marks_encrypted')
                if marks_encrypted:
                    print("\nAttempting to decrypt marks (should fail)...")
                    try:
                        cipher_rsa = PKCS1_OAEP.new(server_rsa_public_key)
                        marks = cipher_rsa.decrypt(marks_encrypted)
                        print(f"Decrypted marks: {marks.decode()}")
                    except Exception as e:
                        print("Failed to decrypt marks. Access denied.")

                # Try to modify marks and send to server
                modify = input("Do you want to modify marks and send to server? (yes/no): ")
                if modify.lower() == 'yes':
                    new_marks = input("Enter new marks: ")
                    new_data = f"{new_marks},{attendance}"
                    new_hash_obj = SHA256.new(new_data.encode())
                    new_hash_hex = new_hash_obj.hexdigest()
                    print(f"\nNew SHA256 Hash of data: {new_hash_hex}")

                    # Assistant cannot sign the data properly, but may attempt to send
                    # For demonstration, assistant sends the modified data without valid signature
                    message = {
                        'role': 'assistant',
                        'ciphertext': None,  # No valid ciphertext
                        'signature': None,  # Cannot sign without private key
                        'hash_hex': new_hash_hex,
                        'modified_data': new_data
                    }
                    # Connect to server and send data
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect(('localhost', 12346))
                    client_socket.sendall(pickle.dumps(message))
                    client_socket.close()
                    print("Modified data sent to server.")

        elif choice == '3':
            print("Exiting.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
