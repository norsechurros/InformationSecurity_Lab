from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_message(key, message):
    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), DES3.block_size))
    return ciphertext

def decrypt_message(key, ciphertext):
    cipher = DES3.new(key, DES3.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext.decode()

def main():
    message = "Classified Text"

    # Generate a random valid 24-byte key for Triple DES
    key = DES3.adjust_key_parity(get_random_bytes(24))

    # Encrypt
    ciphertext = encrypt_message(key, message)
    print("Ciphertext (hex):", ciphertext.hex())

    # Decrypt
    decrypted_message = decrypt_message(key, ciphertext)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
