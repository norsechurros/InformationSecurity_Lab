from Crypto.Cipher import AES
from binascii import unhexlify, hexlify

def aes_ctr_encrypt(key, nonce, message):
    # Create AES cipher in CTR mode using the given key and nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Encrypt the message
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return ciphertext

def aes_ctr_decrypt(key, nonce, ciphertext):
    # Create AES cipher in CTR mode for decryption using the same key and nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

def main():
    # The key provided (128-bit key)
    key = unhexlify("0123456789ABCDEF0123456789ABCDEF")  # 16-byte (128-bit) key
    
    # The nonce (8-byte nonce)
    nonce = unhexlify("0000000000000000")  # Convert the 16-hex digit nonce to bytes
    
    # The message to be encrypted
    message = "Cryptography Lab Exercise"
    
    # Encrypt the message
    ciphertext = aes_ctr_encrypt(key, nonce, message)
    print(f"Ciphertext (Hex): {hexlify(ciphertext).decode()}")
    
    # Decrypt the ciphertext to retrieve the original message
    decrypted_message = aes_ctr_decrypt(key, nonce, ciphertext)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
