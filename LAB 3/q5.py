import time
from Crypto.Util.number import getPrime, inverse
import random

# Diffie-Hellman Key Generation (Private and Public keys)
def generate_dh_keypair(p, g):
    private_key = random.randint(1, p - 2)  # Private key: random number in the range [1, p-2]
    public_key = pow(g, private_key, p)  # Public key: g^private_key mod p
    return private_key, public_key

# Compute the shared secret
def compute_shared_secret(their_public_key, my_private_key, p):
    shared_secret = pow(their_public_key, my_private_key, p)  # (their_public_key^my_private_key) mod p
    return shared_secret

# Measure the time for key generation and shared secret computation
def measure_dh_performance():
    # Step 1: Select a large prime modulus p and a generator g
    p = getPrime(2048)  # Generate a large prime (2048 bits)
    g = 2  # Typically, g is 2 or 5

    print("Prime p and generator g chosen for Diffie-Hellman key exchange.")
    
    # Step 2: Peer 1 generates private/public key pair
    start_time = time.time()
    private_key_1, public_key_1 = generate_dh_keypair(p, g)
    keygen_time_1 = time.time() - start_time

    # Step 3: Peer 2 generates private/public key pair
    start_time = time.time()
    private_key_2, public_key_2 = generate_dh_keypair(p, g)
    keygen_time_2 = time.time() - start_time

    # Step 4: Peer 1 and Peer 2 exchange public keys and compute the shared secret
    start_time = time.time()
    shared_secret_1 = compute_shared_secret(public_key_2, private_key_1, p)  # Peer 1 computes the shared secret
    shared_secret_2 = compute_shared_secret(public_key_1, private_key_2, p)  # Peer 2 computes the shared secret
    key_exchange_time = time.time() - start_time

    # Step 5: Verify that the shared secret is the same for both peers
    assert shared_secret_1 == shared_secret_2, "Shared secrets do not match! Something went wrong."
    
    print(f"Shared secret successfully computed: {shared_secret_1}")
    
    # Print performance metrics
    print(f"Peer 1 Key Generation Time: {keygen_time_1:.4f} seconds")
    print(f"Peer 2 Key Generation Time: {keygen_time_2:.4f} seconds")
    print(f"Key Exchange Time: {key_exchange_time:.4f} seconds")

if __name__ == "__main__":
    measure_dh_performance()
