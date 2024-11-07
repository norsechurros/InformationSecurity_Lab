from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes, random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.number import getPrime
import sys

def diffie_hellman_key_exchange():
    # Simulate Diffie-Hellman Key Exchange between Alice and Bob

    # Generate prime p and generator g
    p = getPrime(256)
    g = 2  # Simple generator

    print(f"Diffie-Hellman parameters:")
    print(f"p (prime): {p}")
    print(f"g (generator): {g}")

    # Alice's private key and public key
    a = random.randint(1, p - 1)
    A = pow(g, a, p)
    print(f"\nAlice's private key (a): {a}")
    print(f"Alice's public key (A): {A}")

    # Bob's private key and public key
    b = random.randint(1, p - 1)
    B = pow(g, b, p)
    print(f"\nBob's private key (b): {b}")
    print(f"Bob's public key (B): {B}")

    # Exchange public keys and compute shared secret
    # Alice computes shared secret
    shared_secret_alice = pow(B, a, p)
    print(f"\nAlice computes shared secret: {shared_secret_alice}")

    # Bob computes shared secret
    shared_secret_bob = pow(A, b, p)
    print(f"Bob computes shared secret: {shared_secret_bob}")

    if shared_secret_alice == shared_secret_bob:
        print("Shared secrets match. Key exchange successful.")
    else:
        print("Shared secrets do not match. Key exchange failed.")
        sys.exit(1)

    # Derive AES key from shared secret
    shared_secret_bytes = shared_secret_alice.to_bytes((shared_secret_alice.bit_length() + 7) // 8, 'big')
    salt = b'salt'  # In practice, use a secure random salt
    aes_key = PBKDF2(shared_secret_bytes, salt, dkLen=16)
    print(f"\nDerived AES key from shared secret: {aes_key.hex()}")

    return aes_key

def aes_encrypt_decrypt(message, key):
    # Encrypt the message using AES
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    ciphertext = ct_bytes
    print(f"\nAES Encryption:")
    print(f"Plaintext: {message}")
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt the message
    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher_dec.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size).decode('utf-8')
    print(f"\nAES Decryption:")
    print(f"Decrypted plaintext: {plaintext}")

    return ciphertext, iv

def sha256_hash(message):
    # Hash the message using SHA-256
    hash_obj = SHA256.new(message.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()
    print(f"\nSHA-256 Hash:")
    print(f"Message: {message}")
    print(f"Hash: {hash_hex}")
    return hash_obj

def rsa_sign_verify(message_hash):
    # Generate RSA keys
    key = RSA.generate(1024)  # Small key size for demonstration
    private_key = key
    public_key = key.publickey()
    print(f"\nRSA Keys:")
    print(f"Private key (PEM format):\n{private_key.export_key().decode('utf-8')}")
    print(f"Public key (PEM format):\n{public_key.export_key().decode('utf-8')}")

    # Sign the hash
    signature = pkcs1_15.new(private_key).sign(message_hash)
    print(f"\nRSA Signature:")
    print(f"Signature: {signature.hex()}")

    # Verify the signature
    try:
        pkcs1_15.new(public_key).verify(message_hash, signature)
        print("Signature verification successful.")
    except (ValueError, TypeError):
        print("Signature verification failed.")

    return signature, public_key

def rsa_homomorphic_property():
    # Demonstrate the homomorphic property of RSA encryption
    # Encrypt m1 and m2, multiply ciphertexts, decrypt result, compare with m1 * m2 mod n

    # Generate RSA keys
    key = RSA.generate(1024)  # Small key size for demonstration
    n = key.n
    e = key.e
    d = key.d
    print(f"\nRSA Keys for Homomorphic Property:")
    print(f"n: {n}")
    print(f"e: {e}")
    print(f"d: {d}")

    # Messages m1 and m2
    m1 = 42
    m2 = 13
    print(f"\nMessages:")
    print(f"m1: {m1}")
    print(f"m2: {m2}")

    # Encrypt messages
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)
    print(f"\nEncrypted Messages:")
    print(f"c1: {c1}")
    print(f"c2: {c2}")

    # Multiply ciphertexts
    c_mul = (c1 * c2) % n
    print(f"\nHomomorphic Operation:")
    print(f"c1 * c2 mod n: {c_mul}")

    # Decrypt the result
    m_mul = pow(c_mul, d, n)
    print(f"\nDecrypted Result:")
    print(f"Decrypted m1 * m2 mod n: {m_mul}")

    # Compare with m1 * m2 mod n
    expected = (m1 * m2) % n
    print(f"Expected m1 * m2 mod n: {expected}")

    if m_mul == expected:
        print("Homomorphic property verified.")
    else:
        print("Homomorphic property verification failed.")

def main():
    # Diffie-Hellman Key Exchange
    aes_key = diffie_hellman_key_exchange()

    # Message to encrypt
    message = "Hello, this is a test message."

    # AES Encryption and Decryption
    ciphertext, iv = aes_encrypt_decrypt(message, aes_key)

    # SHA-256 Hashing
    message_hash = sha256_hash(message)

    # RSA Signing and Verification
    signature, public_key = rsa_sign_verify(message_hash)

    # Demonstrate RSA Homomorphic Property
    rsa_homomorphic_property()

if __name__ == "__main__":
    main()
