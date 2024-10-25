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

def rabin_keygen(bits):
    """Generates a Rabin key pair (public and private keys)."""
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    n = p * q
    public_key = n
    private_key = (p, q)
    return public_key, private_key

def rabin_encrypt(plaintext, public_key):
    """Encrypts the plaintext using the public key."""
    n = public_key
    ciphertext = pow(plaintext, 2, n)  # m^2 mod n
    return ciphertext

def rabin_decrypt(ciphertext, private_key):
    """Decrypts the ciphertext using the private key."""
    p, q = private_key
    n = p * q

    # Compute the four possible square roots using the Chinese Remainder Theorem
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    # Combine results using the Chinese Remainder Theorem
    q_inv = modinv(q, p)
    x1 = (q * q_inv * mp + p * ((q - q_inv) % q) * mq) % n
    x2 = (n - x1) % n
    x3 = (q * q_inv * mq + p * ((q - q_inv) % q) * mp) % n
    x4 = (n - x3) % n

    # Return all four possible square roots
    return x1, x2, x3, x4

def homomorphic_multiply(ciphertext1, ciphertext2, public_key):
    """Performs homomorphic multiplication of two ciphertexts."""
    n = public_key
    return (ciphertext1 * ciphertext2) % n

# Rabin key generation
public_key, private_key = rabin_keygen(512)

# Original plaintexts
plaintext1 = 7
plaintext2 = 3

# Encrypt the plaintexts
ciphertext1 = rabin_encrypt(plaintext1, public_key)
ciphertext2 = rabin_encrypt(plaintext2, public_key)

print(f"Ciphertext of {plaintext1}: {ciphertext1}")
print(f"Ciphertext of {plaintext2}: {ciphertext2}")

# Perform homomorphic multiplication of the ciphertexts
ciphertext_product = homomorphic_multiply(ciphertext1, ciphertext2, public_key)

print(f"Encrypted result of multiplication: {ciphertext_product}")

# Decrypt the result of the homomorphic multiplication
decrypted_product = rabin_decrypt(ciphertext_product, private_key)

print(f"Decrypted results of multiplication (four possible values): {decrypted_product}")

# Now you can choose which of the four decrypted values is the correct one
