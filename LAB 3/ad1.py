from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import random

# Helper function to split the message into smaller chunks
def split_message(message, max_length):
    return [message[i:i + max_length] for i in range(0, len(message), max_length)]

# ElGamal Encryption for chunks
def elgamal_encrypt_chunk(p, g, h, message_chunk):
    m = bytes_to_long(message_chunk.encode())  # Convert chunk to an integer
    if m >= p:
        raise ValueError("Message chunk too large for the modulus p")
    
    y = random.randint(1, p - 2)  # Random number y for encryption
    c1 = pow(g, y, p)  # c1 = g^y mod p
    s = pow(h, y, p)  # s = h^y mod p
    c2 = (m * s) % p  # c2 = m * s mod p
    return c1, c2

# ElGamal Decryption for chunks
def elgamal_decrypt_chunk(p, x, c1, c2):
    s = pow(c1, x, p)  # s = c1^x mod p
    s_inv = inverse(s, p)  # Modular inverse of s mod p
    m = (c2 * s_inv) % p  # m = c2 * s_inv mod p
    message_chunk = long_to_bytes(m).decode()  # Convert integer back to string
    return message_chunk

# ElGamal Encryption for the entire message
def elgamal_encrypt(p, g, h, message):
    max_chunk_size = (p.bit_length() // 8) - 1  # Max length of message chunk
    if max_chunk_size <= 0:
        raise ValueError("Modulus p is too small to encrypt the message.")
    
    message_chunks = split_message(message, max_chunk_size)
    
    ciphertext = []
    for chunk in message_chunks:
        c1, c2 = elgamal_encrypt_chunk(p, g, h, chunk)
        ciphertext.append((c1, c2))
    
    return ciphertext

# ElGamal Decryption for the entire message
def elgamal_decrypt(p, x, ciphertext):
    decrypted_message = ""
    
    for c1, c2 in ciphertext:
        decrypted_chunk = elgamal_decrypt_chunk(p, x, c1, c2)
        decrypted_message += decrypted_chunk
    
    return decrypted_message

def main():
    # Given parameters for ElGamal encryption
    p = 7919
    g = 2
    h = 6465
    x = 2999  # Private key

    # The message to encrypt
    message = "Asymmetric Algorithms"

    try:
        # Encrypt the message
        print(f"Original message: {message}")
        ciphertext = elgamal_encrypt(p, g, h, message)
        print(f"Ciphertext: {ciphertext}")

        # Decrypt the ciphertext
        decrypted_message = elgamal_decrypt(p, x, ciphertext)
        print(f"Decrypted message: {decrypted_message}")

    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()
