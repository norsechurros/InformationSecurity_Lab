import hashlib
import random
from math import gcd

# Utility function to calculate modular inverse using the Extended Euclidean Algorithm
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

# Generate hash digest using SHA-1
def sha1_hash(message):
    hasher = hashlib.sha1()
    hasher.update(message.encode('utf-8'))
    return int(hasher.hexdigest(), 16)  # Return the hash as an integer

# Example usage:

# Step 1: Key generation with small prime numbers
p = 467  # A small prime number
g = 2    # Generator
public_key, private_key = generate_keys(p, g)

print("Public key:", public_key)
print("Private key:", private_key)

# Step 2: Take a message and compute the hash using SHA-1
message = "Hello, ElGamal!"
message_hash = sha1_hash(message)
print("Original message hash (SHA-1):", message_hash)

# Step 3: Encrypt the hash (treated as the message to be encrypted)
ciphertext = elgamal_encrypt(message_hash, public_key)
print("Encrypted message:", ciphertext)

# Step 4: Sign the hash
signature = elgamal_sign(message_hash, private_key, p, g)
print("Digital Signature:", signature)

# Step 5: Decrypt the message
decrypted_message_hash = elgamal_decrypt(ciphertext, private_key, p)
print("Decrypted message hash:", decrypted_message_hash)

# Step 6: Verify the signature
is_signature_valid = elgamal_verify(message_hash, signature, public_key)
print("Is the signature valid?", is_signature_valid)

# Step 7: Modify the message and show the rehash
modified_message = "Hello, ElGamal! Modified"
modified_message_hash = sha1_hash(modified_message)
print("Modified message hash (SHA-1):", modified_message_hash)

# Demonstrate the hash changes
if message_hash != modified_message_hash:
    print("The message was modified, and the hash has changed.")

# Step 8: Demonstrate the homomorphic property of ElGamal encryption
message2 = "Hello, world!"
message2_hash = sha1_hash(message2)
ciphertext2 = elgamal_encrypt(message2_hash, public_key)

# Homomorphic addition of ciphertexts
combined_c1 = (ciphertext[0] * ciphertext2[0]) % p
combined_c2 = (ciphertext[1] * ciphertext2[1]) % p
combined_ciphertext = (combined_c1, combined_c2)

# Decrypt the combined ciphertext
combined_decrypted_hash = elgamal_decrypt(combined_ciphertext, private_key, p)
combined_plaintext_sum = message_hash + message2_hash

print("Decrypted sum of message hashes (homomorphic):", combined_decrypted_hash)
print("Expected sum of message hashes:", combined_plaintext_sum)
