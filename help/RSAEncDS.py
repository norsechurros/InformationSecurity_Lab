import random

# Utility function to calculate the greatest common divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Utility function to compute modular inverse using the Extended Euclidean Algorithm
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# Generate RSA keys (public and private)
def generate_rsa_keys(bits=512):
    p = random_prime(bits)
    q = random_prime(bits)
    n = p * q  # n = p * q (part of public key)
    phi = (p - 1) * (q - 1)

    e = 65537  # Common choice for e (public exponent)
    d = modinv(e, phi)  # Private key exponent d = e^(-1) mod phi

    return (n, e), (n, d)  # Public key (n, e) and private key (n, d)

# RSA encryption
def rsa_encrypt(message, public_key):
    n, e = public_key
    ciphertext = pow(message, e, n)  # c = m^e mod n
    return ciphertext

# RSA decryption
def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    message = pow(ciphertext, d, n)  # m = c^d mod n
    return message

# RSA signature generation
def rsa_sign(message, private_key):
    n, d = private_key
    signature = pow(message, d, n)  # s = m^d mod n
    return signature

# RSA signature verification
def rsa_verify(message, signature, public_key):
    n, e = public_key
    verified_message = pow(signature, e, n)  # m = s^e mod n
    return verified_message == message

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
public_key, private_key = generate_rsa_keys()

print("Public key (n, e):", public_key)
print("Private key (n, d):", private_key)

# Step 2: Encrypt a message
message = 123  # Example message (must be an integer)
ciphertext = rsa_encrypt(message, public_key)
print("Ciphertext:", ciphertext)

# Step 3: Decrypt the message
decrypted_message = rsa_decrypt(ciphertext, private_key)
print("Decrypted message:", decrypted_message)

# Step 4: Sign the message
