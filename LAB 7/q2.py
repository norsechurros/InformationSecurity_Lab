import random
from Crypto.Util import number

# RSA Key Generation
def generate_rsa_keypair(bits=2048):
    e = 65537  # Standard value for e
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # Calculate d such that (e * d) % phi = 1
    return (e, d, n)

# RSA Encryption
def rsa_encrypt(m, e, n):
    return pow(m, e, n)

# RSA Decryption
def rsa_decrypt(c, d, n):
    return pow(c, d, n)

# Main Program
def main():
    # Generate RSA key pair
    e, d, n = generate_rsa_keypair(bits=1024)  # Generate 1024-bit RSA key pair

    # Original integers
    m1 = 7
    m2 = 3

    # Encrypt the integers
    c1 = rsa_encrypt(m1, e, n)
    c2 = rsa_encrypt(m2, e, n)
    print(f"Ciphertext 1 (Encrypted 7): {c1}")
    print(f"Ciphertext 2 (Encrypted 3): {c2}")

    # Multiplying the ciphertexts (homomorphic property)
    c_product = (c1 * c2) % n
    print(f"Encrypted product (Ciphertext 1 * Ciphertext 2): {c_product}")

    # Decrypt the result
    decrypted_product = rsa_decrypt(c_product, d, n)
    print(f"Decrypted product: {decrypted_product}")

    # Verify the result
    expected_product = m1 * m2
    print(f"Expected product: {expected_product}")

    if decrypted_product == expected_product:
        print("The decrypted product matches the expected product!")
    else:
        print("The decrypted product does NOT match the expected product.")

if __name__ == "__main__":
    main()
