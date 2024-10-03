import socket
import random

# Diffie-Hellman Key Generation
def diffie_hellman_keygen(p, g):
    private_key = random.randint(1, p - 2)  # Server's private key
    public_key = pow(g, private_key, p)     # Server's public key
    return private_key, public_key

def main():
    # Define parameters
    p = 23  # Prime number
    g = 5   # Generator

    # Set up the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)
    print("Server listening on port 8080...")
    
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Generate server's DH keys
    private_key, public_key = diffie_hellman_keygen(p, g)
    print(f"Server Public Key: {public_key}")
    
    # Send server's public key to client
    conn.send(str(public_key).encode())
    
    # Receive client's public key
    client_public_key = int(conn.recv(1024).decode())
    print(f"Client's Public Key: {client_public_key}")
    
    # Calculate shared secret
    shared_secret = pow(client_public_key, private_key, p)
    print(f"Server Shared Secret: {shared_secret}")

    conn.close()

if __name__ == "__main__":
    main()
