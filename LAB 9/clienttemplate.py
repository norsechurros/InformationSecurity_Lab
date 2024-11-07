import socket

def send_data(host='localhost', port=12345, data="Hello, Server!"):
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        # Send data
        client_socket.sendall(data.encode('utf-8'))
        print(f"Sent data: {data}")

        # Wait for a response from the server
        response = client_socket.recv(4096)
        if response:
            print(f"Received response from server: {response.decode('utf-8')}")
        else:
            print("No response received.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()
        print("Client socket closed.")

if __name__ == '__main__':
    send_data()
