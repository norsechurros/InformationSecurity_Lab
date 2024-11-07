import socket
import pickle
from Crypto.PublicKey import RSA, ElGamal
from Crypto.PublicKey.ElGamal import ElGamalKey
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.number import inverse
from collections import defaultdict

# Generate ElGamal keys
elgamal_key = ElGamal.generate(256, get_random_bytes)
elgamal_public_key = elgamal_key.publickey()
p = int(elgamal_key.p)
g = int(elgamal_key.g)

# Store cumulative ciphertexts for each contestor
cumulative_ciphertexts = {
    '0': None,
    '1': None,
}

def elgamal_decrypt(private_key, ciphertext):
    c1, c2 = ciphertext
    c1 = int(c1)
    c2 = int(c2)
    # Convert private_key.x and private_key.p to integers
    s = pow(c1, int(private_key.x), int(private_key.p))
    # Use int() on s to ensure it's an integer
    m = (c2 * inverse(s, int(private_key.p))) % int(private_key.p)
    return m

def elgamal_ciphertext_mul(c1_c2_1, c1_c2_2, p):
    c1_1, c2_1 = c1_c2_1
    c1_2, c2_2 = c1_c2_2
    # Ensure c1 and c2 are integers
    c1 = (int(c1_1) * int(c1_2)) % p
    c2 = (int(c2_1) * int(c2_2)) % p
    return (c1, c2)

def discrete_log(base, h, p):
    # Simple discrete logarithm calculation for small p
    for x in range(p):
        if pow(base, x, p) == h:
            return x
    return None

# Setup server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)
print("Server is listening...")

while True:
    client_socket, addr = server_socket.accept()
    print(f"\nConnected by {addr}")
    data = b''
    while True:
        part = client_socket.recv(4096)
        data += part
        if len(part) < 4096:
            break
    if not data:
        continue

    if data == b'public_key_request':
        # Send ElGamal public key parameters to client
        public_key_params = {
            'p': int(elgamal_public_key.p),
            'g': int(elgamal_public_key.g),
            'y': int(elgamal_public_key.y)
        }
        client_socket.sendall(pickle.dumps(public_key_params))
        client_socket.close()
        continue

    request = pickle.loads(data)

    if 'action' in request and request['action'] == 'tally':
        # Return tally for requested contestor
        contestor = request['contestor']
        cumulative_ciphertext = cumulative_ciphertexts.get(contestor)
        if cumulative_ciphertext is None:
            total_votes = 0
        else:
            # Decrypt cumulative ciphertext to get m_total = g^(total_votes)
            m_total = elgamal_decrypt(elgamal_key, cumulative_ciphertext)
            # Compute discrete logarithm to find total_votes
            total_votes = discrete_log(g, m_total, p)
            if total_votes is None:
                total_votes = 'Error computing total votes'
        # Send total votes back to client
        client_socket.sendall(pickle.dumps(total_votes))
    else:
        # Receive vote
        ciphertext = request['ciphertext']
        signature = request['signature']
        message = request['message']
        client_hash_digest = request.get('hash_digest')
        public_key_rsa_bytes = request['public_key_rsa']
        public_key_rsa = RSA.import_key(public_key_rsa_bytes)
        contestor = request['contestor']

        # Verify the hash digest
        message_hash = SHA256.new(message)
        server_hash_digest = message_hash.hexdigest()
        print(f"\nHash Digest from client: {client_hash_digest}")
        print(f"Hash Digest computed on server: {server_hash_digest}")
        if client_hash_digest == server_hash_digest:
            print("Hashes match. Message integrity verified.")
        else:
            print("Hashes do not match. Message integrity compromised.")

        # Verify digital signature
        try:
            pkcs1_15.new(public_key_rsa).verify(message_hash, signature)
            print("Digital signature verified.")

            # Homomorphic aggregation
            if cumulative_ciphertexts[contestor] is None:
                cumulative_ciphertexts[contestor] = ciphertext
            else:
                cumulative_ciphertexts[contestor] = elgamal_ciphertext_mul(
                    cumulative_ciphertexts[contestor],
                    ciphertext,
                    p
                )
            print(f"Vote for contestor {contestor} added.")
        except (ValueError, TypeError):
            print("Signature verification failed.")
    client_socket.close()
