from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify, hexlify
from Crypto.Random import get_random_bytes

def aes256_encrypt(key, iv, message):
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the message and encrypt
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return ciphertext

def aes256_decrypt(key, iv, ciphertext):
    # Create AES cipher in CBC mode for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt and unpad the message
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def main():
    # The key provided (256-bit key)
    key = unhexlify("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  # 32-byte (256-bit) key
    
    # The message to be encrypted
    message = "Encryption Strength"
    
    # Generate a random 16-byte IV for AES-CBC (128-bit block size for AES)
    iv = get_random_bytes(16)
    
    # Encrypt the message
    ciphertext = aes256_encrypt(key, iv, message)
    print(f"Ciphertext (Hex): {hexlify(ciphertext).decode()}")
    
    # Decrypt the ciphertext to get back the original message
    decrypted_message = aes256_decrypt(key, iv, ciphertext)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
