import random
import math

# Generate large prime numbers for RSA
def generate_prime(bits):
    """Generate a prime number of bit size 'bits'."""
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

def egcd(a, b):
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

def modinv(a, m):
    """Modular inverse using the Extended Euclidean algorithm."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def rsa_keygen(bits):
    """Generates an RSA key pair (public and private keys)."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < phi(n) and gcd(e, phi(n)) == 1
    e = 65537  # Common choice for e
    d = modinv(e, phi_n)
    
    # Public and private keys
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_encrypt(plaintext, public_key):
    """Encrypts the plaintext using the public key."""
    e, n = public_key
    ciphertext = pow(plaintext, e, n)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """Decrypts the ciphertext using the private key."""
    d, n = private_key
    plaintext = pow(ciphertext, d, n)
    return plaintext

def homomorphic_multiply(ciphertext1, ciphertext2, public_key):
    """Performs homomorphic multiplication of two ciphertexts."""
    _, n = public_key
    return (ciphertext1 * ciphertext2) % n

# RSA key generation
public_key, private_key = rsa_keygen(1024)

# Original plaintexts
plaintext1 = 7
plaintext2 = 3

# Encrypt the plaintexts
ciphertext1 = rsa_encrypt(plaintext1, public_key)
ciphertext2 = rsa_encrypt(plaintext2, public_key)

print(f"Ciphertext of {plaintext1}: {ciphertext1}")
print(f"Ciphertext of {plaintext2}: {ciphertext2}")

# Homomorphic multiplication of the ciphertexts
ciphertext_product = homomorphic_multiply(ciphertext1, ciphertext2, public_key)

print(f"Encrypted result of multiplication: {ciphertext_product}")

# Decrypt the product of the ciphertexts
decrypted_product = rsa_decrypt(ciphertext_product, private_key)

print(f"Decrypted result of multiplication: {decrypted_product}")
