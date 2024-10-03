from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
import random

# ElGamal Key Generation
def elgamal_keygen(bits=256):
    p = getPrime(bits)  # Generate a large prime number p
    g = random.randint(2, p - 2)  # Random generator g (2 <= g <= p-2)
    x = random.randint(1, p - 2)  # Private key x (1 <= x <= p-2)
    h = pow(g, x, p)  # h = g^x mod p
    public_key = (p, g, h)
    private_key = x
    return public_key, private_key

# ElGamal Encryption
def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    y = random.randint(1, p - 2)  # Random number y (1 <= y <= p-2)
    c1 = pow(g, y, p)  # c1 = g^y mod p
    s = pow(h, y, p)  # s = h^y mod p
    m = bytes_to_long(message.encode())  # Convert message to an integer
    c2 = (m * s) % p  # c2 = m * s mod p
    return (c1, c2)

# ElGamal Decryption
def elgamal_decrypt(private_key, public_key, ciphertext):
    p, g, h = public_key
    c1, c2 = ciphertext
    x = private_key
    s = pow(c1, x, p)  # s = c1^x mod p
    s_inv = inverse(s, p)  # Modular inverse of s mod p
    m = (c2 * s_inv) % p  # m = c2 * s_inv mod p
    message = long_to_bytes(m)  # Convert integer back to bytes
    return message.decode()

def main():
    message = "Confidential Data"

    # Step 1: Generate public and private keys
    public_key, private_key = elgamal_keygen()

    print(f"Public Key (p, g, h): {public_key}")
    print(f"Private Key (x): {private_key}")

    # Step 2: Encrypt the message
    ciphertext = elgamal_encrypt(public_key, message)
    print(f"Ciphertext: {ciphertext}")

    # Step 3: Decrypt the ciphertext
    decrypted_message = elgamal_decrypt(private_key, public_key, ciphertext)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()
