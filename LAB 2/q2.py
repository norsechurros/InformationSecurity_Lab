from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES Encryption
def encrypt(key, message):
    cipher = AES.new(key, AES.MODE_CBC)  # Create AES cipher in CBC mode
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))  # Pad and encrypt the message
    return cipher.iv, ciphertext  # Return the initialization vector (IV) and ciphertext

# AES Decryption
def decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher for decryption
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Decrypt and unpad the message
    return plaintext.decode()

# Example usage
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")  # 128-bit key
message = "Sensitive Info"

# Encrypt the message
iv, ciphertext = encrypt(key, message)
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the ciphertext
decrypted_message = decrypt(key, iv, ciphertext)
print("Decrypted message:", decrypted_message)
