import random
from hashlib import sha256
from math import gcd

# ElGamal Key Generation
def elgamal_keygen(p, g):
    private_key = random.randint(1, p - 2)  # Private key (x)
    public_key = pow(g, private_key, p)  # Public key (y = g^x mod p)
    return private_key, public_key

# ElGamal Signing
def elgamal_sign(message, p, g, private_key):
    m = int(sha256(message.encode()).hexdigest(), 16)  # Hash message
    k = random.randint(1, p - 2)
    
    # Ensure k is coprime to (p-1)
    while gcd(k, p - 1) != 1:
        k = random.randint(1, p - 2)

    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)  # Modular inverse of k mod (p-1)
    s = ((m - private_key * r) * k_inv) % (p - 1)
    return r, s

# ElGamal Verification
def elgamal_verify(message, signature, p, g, public_key):
    r, s = signature
    if r <= 0 or r >= p:
        return False
    m = int(sha256(message.encode()).hexdigest(), 16)  # Hash message
    v1 = pow(g, m, p)
    v2 = (pow(public_key, r, p) * pow(r, s, p)) % p
    return v1 == v2

# Schnorr Key Generation
def schnorr_keygen(p, g):
    private_key = random.randint(1, p - 2)  # Private key (x)
    public_key = pow(g, private_key, p)  # Public key (y = g^x mod p)
    return private_key, public_key

# Schnorr Signing
def schnorr_sign(message, p, g, private_key):
    k = random.randint(1, p - 2)  # Random nonce
    r = pow(g, k, p)  # r = g^k mod p
    e = int(sha256((str(r) + message).encode()).hexdigest(), 16)  # Hash r and message
    s = (k + e * private_key) % (p - 1)
    return r, s

# Schnorr Verification
def schnorr_verify(message, signature, p, g, public_key):
    r, s = signature
    e = int(sha256((str(r) + message).encode()).hexdigest(), 16)  # Hash r and message
    v1 = pow(g, s, p)
    v2 = (r * pow(public_key, e, p)) % p
    return v1 == v2

# Example usage
if __name__ == "__main__":
    # Prime number p and generator g (in practice, these should be large secure values)
    p = 23  # A small prime for example (in practice, use large primes like 2048-bit)
    g = 5   # A small generator
    
    message = "Hello, this is a test message."

    # ElGamal Example
    print("ElGamal Signature Example:")
    elgamal_private_key, elgamal_public_key = elgamal_keygen(p, g)
    elgamal_signature = elgamal_sign(message, p, g, elgamal_private_key)
    print(f"ElGamal Signature: {elgamal_signature}")
    valid = elgamal_verify(message, elgamal_signature, p, g, elgamal_public_key)
    print(f"ElGamal Signature valid: {valid}\n")

    # Schnorr Example
    print("Schnorr Signature Example:")
    schnorr_private_key, schnorr_public_key = schnorr_keygen(p, g)
    schnorr_signature = schnorr_sign(message, p, g, schnorr_private_key)
    print(f"Schnorr Signature: {schnorr_signature}")
    valid = schnorr_verify(message, schnorr_signature, p, g, schnorr_public_key)
    print(f"Schnorr Signature valid: {valid}")
