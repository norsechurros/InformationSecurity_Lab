from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import randrange_from_seed__trytryagain
import hashlib
import random

# Define elliptic curve parameters (SECP256k1 is a widely used elliptic curve)
curve = SECP256k1

def sha256_hash(message):
    """Generates a SHA256 hash of the input message."""
    return hashlib.sha256(message).hexdigest()

# ECC ElGamal Key Generation
def ecc_elgamal_keygen():
    """Generates an ElGamal-like ECC key pair."""
    private_key = SigningKey.generate(curve=curve)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

# ECC ElGamal Encryption
def ecc_elgamal_encrypt(public_key, plaintext):
    """Encrypts the plaintext using the public key."""
    # Choose a random value (k) for encryption
    k = randrange_from_seed__trytryagain(sha256_hash(str(random.random()).encode('utf-8')), curve.order)
    
    # Ciphertext components (kG, plaintext * kG)
    R = k * curve.generator  # Random point on curve
    Pm = plaintext * k * curve.generator  # Point Pm (encoded plaintext)
    
    return (R, Pm)

# ECC ElGamal Decryption
def ecc_elgamal_decrypt(private_key, ciphertext):
    """Decrypts the ciphertext using the private key."""
    R, Pm = ciphertext
    private_num = private_key.privkey.secret_multiplier
    
    # Decrypt the plaintext
    plaintext_point = Pm - (private_num * R)
    
    return plaintext_point

# ECC Homomorphic Multiplication
def homomorphic_multiply(ciphertext1, ciphertext2):
    """Performs homomorphic multiplication of two ciphertexts."""
    R1, Pm1 = ciphertext1
    R2, Pm2 = ciphertext2
    
    # Perform component-wise multiplication of the ciphertexts
    R_product = R1 + R2
    Pm_product = Pm1 + Pm2
    
    return (R_product, Pm_product)

# ECC ElGamal Key Generation
private_key, public_key = ecc_elgamal_keygen()

# Original plaintexts (as integers, because ECC works over numbers)
plaintext1 = 7
plaintext2 = 3

# Encrypt the plaintexts
ciphertext1 = ecc_elgamal_encrypt(public_key, plaintext1)
ciphertext2 = ecc_elgamal_encrypt(public_key, plaintext2)

print(f"Ciphertext of {plaintext1}: {ciphertext1}")
print(f"Ciphertext of {plaintext2}: {ciphertext2}")

# Perform homomorphic multiplication (component-wise addition on the elliptic curve)
ciphertext_product = homomorphic_multiply(ciphertext1, ciphertext2)

print(f"Encrypted result of multiplication (as a point on the curve): {ciphertext_product}")

# Decrypt the product of the homomorphic multiplication
decrypted_product = ecc_elgamal_decrypt(private_key, ciphertext_product)

print(f"Decrypted result of multiplication: {decrypted_product}")
