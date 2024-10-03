import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def time_encryption_decryption(cipher_class, key, message, mode):
    # Create cipher object
    cipher = cipher_class.new(key, mode)
    
    # Encrypt the message
    start_time = time.perf_counter()
    ciphertext = cipher.encrypt(pad(message.encode(), cipher.block_size))
    encrypt_time = time.perf_counter() - start_time
    
    # Decrypt the message
    cipher = cipher_class.new(key, mode)
    start_time = time.perf_counter()
    plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode()
    decrypt_time = time.perf_counter() - start_time
    
    return encrypt_time, decrypt_time

def main():
    message = "Performance Testing of Encryption Algorithms" * 1000  # Larger message
    
    # DES configuration
    des_key = b'8bytekey'  # DES requires a key of exactly 8 bytes
    des_mode = DES.MODE_ECB  # Using ECB mode for simplicity
    
    # AES-256 configuration
    aes_key = get_random_bytes(32)  # 32 bytes key for AES-256
    aes_mode = AES.MODE_ECB  # Using ECB mode for simplicity
    
    # Measure DES
    des_encrypt_time, des_decrypt_time = time_encryption_decryption(DES, des_key, message, des_mode)
    
    # Measure AES-256
    aes_encrypt_time, aes_decrypt_time = time_encryption_decryption(AES, aes_key, message, aes_mode)
    
    print(f"DES Encryption Time: {des_encrypt_time:.6f} seconds")
    print(f"DES Decryption Time: {des_decrypt_time:.6f} seconds")
    print(f"AES-256 Encryption Time: {aes_encrypt_time:.6f} seconds")
    print(f"AES-256 Decryption Time: {aes_decrypt_time:.6f} seconds")

if __name__ == "__main__":
    main()
