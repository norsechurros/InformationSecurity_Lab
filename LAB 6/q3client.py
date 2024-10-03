import socket
import random

# Diffie-Hellman Key Generation
def diffie_hellman_keygen(p, g):
    private_key = random.randint(1, p - 2)  # Client's private key
    public_key = pow(g, private_key, p)     # Client's public key
    return private_key, public_key

def main():
    # Define parameters
    p = 23  # Prime number
    g = 5   # Generator

    # Set up client connection to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    # Generate client's DH keys
    private_key, public_key = diffie_hellman_keygen(p, g)
    print(f"Client Public Key: {public_key}")

    # Receive server's public key
    server_public_key = int(client_socket.recv(1024).decode())
    print(f"Server's Public Key: {server_public_key}")
    
    # Send client's public key to server
    client_socket.send(str(public_key).encode())
    
    # Calculate shared secret
    shared_secret = pow(server_public_key, private_key, p)
    print(f"Client Shared Secret: {shared_secret}")

    client_socket.close()

if __name__ == "__main__":
    main()
