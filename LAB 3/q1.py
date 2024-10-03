from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# RSA Key Generation
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()  # Export private key
    public_key = key.publickey().export_key()  # Export public key
    return public_key, private_key

# RSA Encryption
def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(message.encode())  # Encode the message before encrypting
    return ciphertext

# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()  # Decode back to string

def main():
    message = "Asymmetric Encryption"

    # Step 1: Generate RSA key pair
    public_key, private_key = generate_rsa_keypair()

    # Display keys (for demonstration purposes)
    print("Public Key (n, e):")
    print(public_key.decode())
    print("Private Key (n, d):")
    print(private_key.decode())

    # Step 2: Encrypt the message using the public key
    ciphertext = rsa_encrypt(public_key, message)
    print("Ciphertext (hex):", ciphertext.hex())

    # Step 3: Decrypt the ciphertext using the private key
    decrypted_message = rsa_decrypt(private_key, ciphertext)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
