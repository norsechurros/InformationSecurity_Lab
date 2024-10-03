import random
from math import gcd
from sympy import mod_inverse

# L function for Paillier decryption
def L(u, n):
    return (u - 1) // n

# Paillier Key Generation
def generate_paillier_keys(bit_length=512):
    # Step 1: Choose two large primes p and q
    p = random_prime(bit_length)
    q = random_prime(bit_length)
    
    # Step 2: Compute n = p * q
    n = p * q
    n_squared = n * n
    
    # Step 3: Compute lambda = lcm(p-1, q-1)
    lambda_val = lcm(p - 1, q - 1)
    
    # Step 4: Choose g such that g in Z_{n^2}*
    g = n + 1  # Typically, g = n + 1 is chosen for simplicity
    
    # Step 5: Compute mu = (L(g^lambda mod n^2))^-1 mod n
    x = pow(g, lambda_val, n_squared)
    mu = mod_inverse(L(x, n), n)
    
    # Public and private keys
    public_key = (n, g)
    private_key = (lambda_val, mu)
    
    return public_key, private_key

# Encryption: Paillier encryption of message m with public key (n, g)
def paillier_encrypt(m, public_key):
    n, g = public_key
    n_squared = n * n
    
    # Choose a random r from Z_n*
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    
    # Encryption formula: c = g^m * r^n mod n^2
    c = (pow(g, m, n_squared) * pow(r, n, n_squared)) % n_squared
    return c

# Decryption: Paillier decryption of ciphertext c with private key (lambda, mu)
def paillier_decrypt(c, public_key, private_key):
    n, g = public_key
    lambda_val, mu = private_key
    n_squared = n * n
    
    # Decryption formula: m = L(c^lambda mod n^2) * mu mod n
    x = pow(c, lambda_val, n_squared)
    m = (L(x, n) * mu) % n
    return m

# Helper functions to generate large primes and compute lcm
def random_prime(bit_length):
    return random.getrandbits(bit_length) | 1  # Ensure it's odd (likely prime for demonstration)

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

# Example usage
if __name__ == "__main__":
    # Key generation
    public_key, private_key = generate_paillier_keys()
    
    # Encrypt two integers (e.g., 15 and 25)
    m1 = 15
    m2 = 25
    print(f"Original messages: {m1}, {m2}")
    
    c1 = paillier_encrypt(m1, public_key)
    c2 = paillier_encrypt(m2, public_key)
    print(f"Ciphertexts: {c1}, {c2}")
    
    # Perform homomorphic addition on the encrypted integers (without decrypting)
    # c1 * c2 mod n^2 gives the encrypted sum of m1 + m2
    n, g = public_key
    encrypted_sum = (c1 * c2) % (n * n)
    print(f"Encrypted sum: {encrypted_sum}")
    
    # Decrypt the result of the addition
    decrypted_sum = paillier_decrypt(encrypted_sum, public_key, private_key)
    print(f"Decrypted sum: {decrypted_sum}")

    # Verify the sum matches m1 + m2
    expected_sum = m1 + m2
    print(f"Expected sum: {expected_sum}")
    assert decrypted_sum == expected_sum, "Decryption failed to match the original sum"
    print("Success! Decrypted sum matches the original sum.")
