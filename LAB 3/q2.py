from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# Generate ECC key pair (Private and Public)
def generate_ecc_keypair():
    private_key = ECC.generate(curve='P-256')  # Generate ECC key pair with curve P-256
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt message using ECC public key and AES (ECIES scheme)
def encrypt_message(public_key, message):
    # Step 1: Derive a shared secret from the public key (just for demonstration, use point x-coordinate)
    shared_secret = SHA256.new(public_key.pointQ.x.to_bytes(32, 'big')).digest()

    # Step 2: Derive AES key from shared secret using scrypt KDF
    salt = get_random_bytes(16)  # Generate a salt to use with scrypt
    aes_key = scrypt(shared_secret, salt, 32, N=2**14, r=8, p=1)

    # Step 3: Encrypt the message using AES (CBC mode)
    iv = get_random_bytes(16)  # Initialization vector for AES
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))  # Pad and encrypt the message

    return iv, salt, ciphertext

# Decrypt the ciphertext using ECC private key and AES (ECIES scheme)
def decrypt_message(private_key, iv, salt, ciphertext):
    # Step 1: Derive the shared secret using the private key
    shared_secret = SHA256.new(private_key.pointQ.x.to_bytes(32, 'big')).digest()

    # Step 2: Derive AES key from shared secret using scrypt KDF
    aes_key = scrypt(shared_secret, salt, 32, N=2**14, r=8, p=1)

    # Step 3: Decrypt the ciphertext using AES (CBC mode)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode()  # Convert bytes back to string


def main():
    message = "Secure Transactions"

    # Step 1: Generate ECC key pair (private and public keys)
    private_key, public_key = generate_ecc_keypair()

    # Step 2: Encrypt the message using the public key
    iv, salt, ciphertext = encrypt_message(public_key, message)
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # Step 3: Decrypt the ciphertext using the private key
    decrypted_message = decrypt_message(private_key, iv, salt, ciphertext)
    print(f"Decrypted message: {decrypted_message}")


if __name__ == "__main__":
    main()
