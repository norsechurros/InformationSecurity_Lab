import socket
import hashlib

# Client configuration
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def start_client():
    data = "Hello, this is a test message.".encode()

    # Compute local hash
    local_hash = compute_hash(data)
    print(f"Local hash: {local_hash}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Send data to the server
        s.sendall(data)

        # Receive the hash from the server
        server_hash = s.recv(1024).decode()
        print(f"Received hash from server: {server_hash}")

        # Compare hashes
        if local_hash == server_hash:
            print("Data integrity verified: Hashes match.")
        else:
            print("Data corruption detected: Hashes do not match.")

if __name__ == "__main__":
    start_client()
