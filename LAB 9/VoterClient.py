import socket
import pickle
from Crypto.PublicKey import RSA, ElGamal
from Crypto.PublicKey.ElGamal import ElGamalKey
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import GCD

# Generate RSA keys for signing (private key)
rsa_key = RSA.generate(1024)
rsa_public_key = rsa_key.publickey()

# Function to request ElGamal public key parameters from server
def get_elgamal_public_key():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 12345))
        client_socket.sendall(b'public_key_request')
        data = b''
        while True:
            part = client_socket.recv(4096)
            if not part:
                break
            data += part
        public_key_params = pickle.loads(data)
        p = public_key_params['p']
        g = public_key_params['g']
        y = public_key_params['y']

        # Reconstruct ElGamal public key
        elgamal_public_key = ElGamalKey()
        elgamal_public_key.p = p
        elgamal_public_key.g = g
        elgamal_public_key.y = y
    return elgamal_public_key

# Get the ElGamal public key from the server
elgamal_public_key = get_elgamal_public_key()
p = int(elgamal_public_key.p)
g = int(elgamal_public_key.g)

def elgamal_encrypt(public_key, m):
    # Select random k
    while True:
        k = random.randint(1, public_key.p - 2)
        if GCD(k, public_key.p - 1) == 1:
            break

    c1 = pow(public_key.g, k, public_key.p)
    s = pow(public_key.y, k, public_key.p)
    c2 = (m * s) % public_key.p

    return (c1, c2), k

def send_vote(voter_name, contestor, vote):
    # Prepare message (voter_name, contestor)
    message = f'{voter_name},{contestor}'.encode()

    # Hash the message
    message_hash = SHA256.new(message)
    hash_digest = message_hash.hexdigest()
    print(f"\nHash Digest of message: {hash_digest}")

    # Represent vote as m = g^v mod p
    v = int(vote)
    m = pow(g, v, p)

    # Encrypt m using ElGamal
    (c1, c2), k = elgamal_encrypt(elgamal_public_key, m)
    ciphertext = (c1, c2)
    print(f"Encrypted Ciphertext:")
    print(f"  c1 = {c1}")
    print(f"  c2 = {c2}")
    print(f"ElGamal Encryption Keys:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    print(f"  y = {elgamal_public_key.y}")
    print(f"  k (random value) = {k}")

    # Sign the hash using RSA
    signature = pkcs1_15.new(rsa_key).sign(message_hash)
    print(f"Digital Signature: {signature.hex()}")

    # Prepare data to send
    data = {
        'ciphertext': ciphertext,
        'signature': signature,
        'message': message,
        'hash_digest': hash_digest,
        'public_key_rsa': rsa_public_key.export_key(),
        'contestor': contestor,
    }

    # Create a new socket connection to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 12345))
        client_socket.sendall(pickle.dumps(data))
        print("Vote sent successfully.")

def request_tally(contestor):
    # Send request to server
    request = {
        'action': 'tally',
        'contestor': str(contestor),
    }

    # Create a new socket connection to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 12345))
        client_socket.sendall(pickle.dumps(request))
        # Receive response
        data = b''
        while True:
            part = client_socket.recv(4096)
            if not part:
                break
            data += part
        tally = pickle.loads(data)
        print(f"Total votes for contestor {contestor}: {tally}")

while True:
    print("\n1. Cast Vote")
    print("2. Show tally for Contestor 0")
    print("3. Show tally for Contestor 1")
    choice = input("Enter your choice: ")

    if choice == '1':
        voter_name = input("Enter voter name: ")
        contestor = input("Enter contestor (0 or 1): ")
        vote = input("Enter vote (0 or 1): ")
        send_vote(voter_name, contestor, vote)
    elif choice == '2':
        request_tally(0)
    elif choice == '3':
        request_tally(1)
    else:
        print("Invalid choice.")
