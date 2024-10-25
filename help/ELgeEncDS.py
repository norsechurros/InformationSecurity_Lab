import random
from math import gcd

# Function to compute modular inverse using the Extended Euclidean Algorithm
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# Generate ElGamal keys (public and private)
def generate_keys(p, g):
    x = random.randint(1, p-2)  # Private key (random x such that 1 < x < p-1)
    h = pow(g, x, p)            # Public key: h = g^x mod p
    return (p, g, h), x          # Return public key (p, g, h) and private key x

# ElGamal encryption
def elgamal_encrypt(message, public_key):
    p, g, h = public_key
    k = random.randint(1, p-2)  # Random k such that 1 < k < p-1
    c1 = pow(g, k, p)           # c1 = g^k mod p
    c2 = (message * pow(h, k, p)) % p  # c2 = m * h^k mod p
    return (c1, c2)

# ElGamal decryption
def elgamal_decrypt(ciphertext, private_key, p):
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)  # s = c1^x mod p
    s_inv = modinv(s, p)         # s_inv is the modular inverse of s mod p
    message = (c2 * s_inv) % p   # message = c2 * s^(-1) mod p
    return message

# ElGamal signature generation
def elgamal_sign(message, private_key, p, g):
    while True:
        k = random.randint(1, p-2)  # Choose random k such that gcd(k, p-1) = 1
        if gcd(k, p-1) == 1:
            break
    r = pow(g, k, p)  # r = g^k mod p
    k_inv = modinv(k, p-1)
    s = (k_inv * (message - private_key * r)) % (p-1)  # s = (m - xr) * k^(-1) mod (p-1)
    return (r, s)

# ElGamal signature verification
def elgamal_verify(message, signature, public_key):
    p, g, h = public_key
    r, s = signature
    if not (1 < r < p):  # Check if r is in the valid range
        return False
    v1 = pow(g, message, p)  # g^m mod p
    v2 = (pow(r, s, p) * pow(h, r, p)) % p  # r^s * h^r mod p
    return v1 == v2

# Example usage:

# Step 1: Key generation
p = 467  # A large prime number
g = 2    # Generator
public_key, private_key = generate_keys(p, g)

# Display the keys
print("Public key:", public_key)
print("Private key:", private_key)

# Step 2: Encrypt a message
message = 123  # Example message (should be an integer in the range [0, p-1])
ciphertext = elgamal_encrypt(message, public_key)
print("Ciphertext:", ciphertext)

# Step 3: Decrypt the message
decrypted_message = elgamal_decrypt(ciphertext, private_key, p)
print("Decrypted message:", decrypted_message)

# Step 4: Sign the message
signature = elgamal_sign(message, private_key, p, g)
print("Signature:", signature)

# Step 5: Verify the signature
is_valid = elgamal_verify(message, signature, public_key)
print("Signature valid?", is_valid)
