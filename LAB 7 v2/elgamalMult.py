import random
import math

def generate_large_prime(bits):
    """Generates a large prime number."""
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p

def is_prime(n, k=40):
    """Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def modinv(a, m):
    """Modular inverse using the Extended Euclidean algorithm."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def egcd(a, b):
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

def elgamal_keygen(bits):
    """Generates an ElGamal key pair (public and private keys)."""
    p = generate_large_prime(bits)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key
    public_key = (p, g, h)
    private_key = x
    return public_key, private_key

def elgamal_encrypt(plaintext, public_key):
    """Encrypts the plaintext using the public key."""
    p, g, h = public_key
    y = random.randint(1, p - 2)
    c1 = pow(g, y, p)
    c2 = (plaintext * pow(h, y, p)) % p
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key, public_key):
    """Decrypts the ciphertext using the private key."""
    c1, c2 = ciphertext
    p, g, h = public_key
    s = pow(c1, private_key, p)
    s_inv = modinv(s, p)
    plaintext = (c2 * s_inv) % p
    return plaintext

def homomorphic_multiply(ciphertext1, ciphertext2, public_key):
    """Performs homomorphic multiplication of two ciphertexts."""
    p, _, _ = public_key
    c1_product = (ciphertext1[0] * ciphertext2[0]) % p
    c2_product = (ciphertext1[1] * ciphertext2[1]) % p
    return (c1_product, c2_product)

# ElGamal key generation
public_key, private_key = elgamal_keygen(512)

# Original plaintexts
plaintext1 = 7
plaintext2 = 3

# Encrypt the plaintexts
ciphertext1 = elgamal_encrypt(plaintext1, public_key)
ciphertext2 = elgamal_encrypt(plaintext2, public_key)

print(f"Ciphertext of {plaintext1}: {ciphertext1}")
print(f"Ciphertext of {plaintext2}: {ciphertext2}")

# Perform homomorphic multiplication of the ciphertexts
ciphertext_product = homomorphic_multiply(ciphertext1, ciphertext2, public_key)

print(f"Encrypted result of multiplication: {ciphertext_product}")

# Decrypt the result of the homomorphic multiplication
decrypted_product = elgamal_decrypt(ciphertext_product, private_key, public_key)

print(f"Decrypted result of multiplication: {decrypted_product}")
