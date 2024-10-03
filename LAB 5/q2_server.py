import socket
import hashlib

# Server configuration
HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Port to listen on

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server is listening on {HOST}:{PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            if not data:
                return

            print(f"Received data: {data.decode()}")

            # Compute the hash of the received data
            received_hash = compute_hash(data)
            print(f"Computed hash: {received_hash}")

            # Send the hash back to the client
            conn.sendall(received_hash.encode())

if __name__ == "__main__":
    start_server()
