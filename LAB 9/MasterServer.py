import socket
from threading import Thread
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Random import random, get_random_bytes
from Crypto.Util.number import getPrime
from Crypto.Math.Numbers import Integer
import pickle

class Server:
    def __init__(self):
        # Generate RSA keys
        self.rsa_key = RSA.generate(2048)
        self.rsa_public_key = self.rsa_key.publickey()
        print("\nServer generated RSA key pair.")

        # Generate ElGamal keys using get_random_bytes
        self.elgamal_key = ElGamal.generate(256, get_random_bytes)
        self.elgamal_public_key = self.elgamal_key.publickey()
        print("Server generated ElGamal key pair.")

        # Store client's ElGamal public key
        self.client_elgamal_public_key = None

        # For demonstration, store marks and attendance
        self.marks_encrypted = None
        self.attendance = None

        # For Diffie-Hellman
        self.dh_p = getPrime(256)
        self.dh_g = 2
        self.dh_b = random.randint(1, self.dh_p - 1)
        self.dh_B = pow(self.dh_g, self.dh_b, self.dh_p)

    def handle_client(self, conn, addr):
        print(f"\nConnected by {addr}")
        data = conn.recv(4096)
        if not data:
            conn.close()
            return

        # Check if the client is requesting public keys
        if data == b'get_public_keys':
            # Send RSA and ElGamal public keys to client
            public_keys = {
                'rsa_public_key': self.rsa_public_key.export_key(),
                'elgamal_public_key': {
                    'p': int(self.elgamal_public_key.p),
                    'g': int(self.elgamal_public_key.g),
                    'y': int(self.elgamal_public_key.y)
                }
            }
            conn.sendall(pickle.dumps(public_keys))
            print("Sent RSA and ElGamal public keys to client.")

            # Receive client's ElGamal public key
            data = conn.recv(4096)
            message = pickle.loads(data)
            client_elgamal_components = message['client_elgamal_public_key']

            # Reconstruct client's ElGamal public key
            self.client_elgamal_public_key = ElGamal.construct((
                Integer(client_elgamal_components['p']),
                Integer(client_elgamal_components['g']),
                Integer(client_elgamal_components['y'])
            ))
            print("Received and reconstructed client's ElGamal public key.")

            # Perform Diffie-Hellman key exchange
            data = conn.recv(4096)
            dh_params = pickle.loads(data)
            A = dh_params['A']

            # Send B, p, g to client
            dh_response = {'B': self.dh_B, 'p': self.dh_p, 'g': self.dh_g}
            conn.sendall(pickle.dumps(dh_response))

            # Compute shared secret
            shared_secret = pow(A, self.dh_b, self.dh_p)
            print(f"Server computed shared secret: {shared_secret}")

            conn.close()
            return

        # Process messages based on role
        message = pickle.loads(data)
        role = message.get('role')
        if role == 'master':
            # Process master's data
            ciphertext = message['ciphertext']
            signature = message['signature']
            hash_hex = message['hash_hex']

            # Decrypt ciphertext
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
            try:
                decrypted_data = cipher_rsa.decrypt(ciphertext)
                decrypted_data = decrypted_data.decode()
                print(f"\nDecrypted data: {decrypted_data}")
            except Exception as e:
                print(f"Failed to decrypt data: {e}")
                conn.close()
                return

            # Verify signature
            hash_obj = SHA256.new(decrypted_data.encode())
            verifier = DSS.new(self.client_elgamal_public_key, 'fips-186-3')
            try:
                verifier.verify(hash_obj, signature)
                print("Signature is valid.")
            except Exception as e:
                print(f"Signature verification failed: {e}")
                conn.close()
                return

            # Verify hash
            calculated_hash_hex = hash_obj.hexdigest()
            if calculated_hash_hex == hash_hex:
                print("Hash matches. Data integrity verified.")
            else:
                print("Hash mismatch. Data may have been tampered with.")
                conn.close()
                return

            # Store the data
            marks, attendance = decrypted_data.split(',')
            self.marks_encrypted = ciphertext  # Store encrypted marks
            self.attendance = attendance
            print("Stored marks and attendance.")
            conn.close()
            return

        elif role == 'assistant':
            request = message.get('request')
            if request == 'get_attendance':
                # Send attendance to assistant
                response = {'attendance': self.attendance}
                conn.sendall(pickle.dumps(response))
                print("Sent attendance to assistant.")
                conn.close()
                return
            else:
                # Assistant is attempting to modify data
                modified_data = message.get('modified_data')
                hash_hex = message.get('hash_hex')
                signature = message.get('signature')

                # Cannot verify signature without valid signature
                if not signature:
                    print("No signature provided. Possible tampering detected.")
                    conn.close()
                    return

                # Verify signature (should fail)
                hash_obj = SHA256.new(modified_data.encode())
                verifier = DSS.new(self.client_elgamal_public_key, 'fips-186-3')
                try:
                    verifier.verify(hash_obj, signature)
                    print("Signature is valid.")
                except Exception as e:
                    print(f"Signature verification failed: {e}")
                    print("Tampering detected.")
                    conn.close()
                    return

                # Verify hash
                calculated_hash_hex = hash_obj.hexdigest()
                if calculated_hash_hex == hash_hex:
                    print("Hash matches. Data integrity verified.")
                else:
                    print("Hash mismatch. Data may have been tampered with.")
                    conn.close()
                    return

                # Since assistant should not modify data, show error
                print("Assistant attempted to modify data. Access denied.")
                conn.close()
                return

        else:
            print("Unknown role or invalid message.")
            conn.close()
            return

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 12346))
        server_socket.listen(5)
        print("\nServer is listening on port 12345.")

        while True:
            conn, addr = server_socket.accept()
            client_thread = Thread(target=self.handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    server = Server()
    server.start_server()

