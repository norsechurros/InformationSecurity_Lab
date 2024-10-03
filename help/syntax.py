from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# AES Encryption/Decryption
def aes_encrypt_decrypt():
    key = get_random_bytes(32)  # AES-256 key
    iv = get_random_bytes(16)   # Initialization vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message = b"Secret message for AES"

    # Encrypt
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    print(f"AES Encrypted: {ciphertext.hex()}")

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print(f"AES Decrypted: {plaintext.decode()}")

# RSA Encryption/Decryption
def rsa_encrypt_decrypt():
    # Generate RSA key pair
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    message = b"RSA encrypted message"

    # Encrypt with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(message)
    print(f"RSA Encrypted: {ciphertext.hex()}")

    # Decrypt with private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    print(f"RSA Decrypted: {plaintext.decode()}")

# RSA Digital Signing/Verification
def rsa_sign_verify():
    message = b"RSA message to sign"
    h = SHA256.new(message)

    # Generate RSA key pair
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    # Sign with private key
    signature = pkcs1_15.new(private_key).sign(h)
    print(f"RSA Signature: {signature.hex()}")

    # Verify with public key
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("RSA Signature verified!")
    except (ValueError, TypeError):
        print("RSA Signature verification failed!")

# ECC Digital Signing/Verification
def ecc_sign_verify():
    # Generate ECC key pair
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()

    message = b"ECC message to sign"
    h = SHA256.new(message)

    # Sign with ECC private key
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    print(f"ECC Signature: {signature.hex()}")

    # Verify with ECC public key
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        print("ECC Signature verified!")
    except ValueError:
        print("ECC Signature verification failed!")

# Password-Based Key Derivation (PBKDF2)
def key_derivation():
    password = b"mysecretpassword"
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    print(f"Derived key: {key.hex()}")

# Hashing (SHA-256)
def hash_message():
    message = b"Message to hash"
    h = SHA256.new(message)
    print(f"SHA-256 Hash: {h.hexdigest()}")

# HMAC (SHA-256)
def hmac_message():
    key = b'Secret key'
    message = b'Message to authenticate'
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(message)
    print(f"HMAC: {hmac.hexdigest()}")

# Example usage
def main():
    print("\n--- AES Encryption/Decryption ---")
    aes_encrypt_decrypt()

    print("\n--- RSA Encryption/Decryption ---")
    rsa_encrypt_decrypt()

    print("\n--- RSA Signing/Verification ---")
    rsa_sign_verify()

    print("\n--- ECC Signing/Verification ---")
    ecc_sign_verify()

    print("\n--- Key Derivation (PBKDF2) ---")
    key_derivation()

    print("\n--- Hashing (SHA-256) ---")
    hash_message()

    print("\n--- HMAC (SHA-256) ---")
    hmac_message()

if __name__ == "__main__":
    main()
