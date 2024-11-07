import socket

def start_server(host='localhost', port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow the socket to reuse the address
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
        print(f"Server started on {host}:{port}")
        # Listen for incoming connections
        server_socket.listen(5)
        print("Server is listening for incoming connections...")

        while True:
            # Wait for a connection
            client_socket, client_address = server_socket.accept()
            try:
                print(f"Connected by {client_address}")

                # Receive data from the client
                data = client_socket.recv(4096)
                if data:
                    # Process the received data
                    print(f"Received data from {client_address}: {data.decode('utf-8')}")
                    # Send a response back to the client
                    response = "Data received successfully."
                    client_socket.sendall(response.encode('utf-8'))
                else:
                    print("No data received.")

            finally:
                # Clean up the connection
                client_socket.close()
                print(f"Connection with {client_address} closed.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == '__main__':
    start_server()
