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

# Generate Rabin keys (public and private)
def generate_rabin_keys():
    # Step 1: Choose two large primes p and q, both congruent to 3 mod 4
    while True:
        p = random_prime(512)
        if p % 4 == 3:
            break
    while True:
        q = random_prime(512)
        if q % 4 == 3:
            break
    n = p * q  # Public key
    private_key = (p, q)  # Private key is (p, q)
    return n, private_key

# Rabin encryption
def rabin_encrypt(message, public_key):
    n = public_key
    ciphertext = (message ** 2) % n  # c = m^2 mod n
    return ciphertext

# Rabin decryption
def rabin_decrypt(ciphertext, private_key, public_key):
    p, q = private_key
    n = public_key

    # Use Chinese remainder theorem to find the four roots
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    
    # Compute the four possible plaintexts using the CRT
    yp = modinv(q, p)
    yq = modinv(p, q)
    
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3

    return r1, r2, r3, r4  # Four possible plaintexts

# Rabin signature
def rabin_sign(message, private_key):
    p, q = private_key
    n = p * q

    # Ensure message is a quadratic residue modulo p and q
    while True:
        m2 = (message ** 2) % n
        if pow(m2, (p - 1) // 2, p) == 1 and pow(m2, (q - 1) // 2, q) == 1:
            return m2

# Rabin signature verification
def rabin_verify(message, signature, public_key):
    n = public_key
    return (signature ** 2) % n == message

# Random prime number generation
def random_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if is_prime(prime_candidate):
            return prime_candidate

# A simple primality test using Miller-Rabin
def is_prime(n, k=5):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Example usage:

# Step 1: Key generation
public_key, private_key = generate_rabin_keys()

print("Public key (n):", public_key)
print("Private key (p, q):", private_key)

# Step 2: Encrypt a message
message = 123  # Example message (must be an integer)
ciphertext = rabin_encrypt(message, public_key)
print("Ciphertext:", ciphertext)

# Step 3: Decrypt the message
decrypted_messages = rabin_decrypt(ciphertext, private_key, public_key)
print("Possible decrypted messages:", decrypted_messages)

# Step 4: Sign the message
signature = rabin_sign(message, private_key)
print("Signature:", signature)

# Step 5: Verify the signature
is_valid = rabin_verify(message, signature, public_key)
print("Signature valid?", is_valid)
