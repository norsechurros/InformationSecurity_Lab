from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def encrypt_des(key, iv, message):
    des_cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = des_cipher.encrypt(pad(message.encode('utf-8'), DES.block_size))
    return ciphertext

def encrypt_aes(key, iv, message):
    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return ciphertext

def main():
    # Five different messages
    messages = [
        "Message One",
        "Message Two",
        "Message Three",
        "Message Four",
        "Message Five"
    ]

    # DES uses an 8-byte key (64 bits, but 56 effective bits due to parity)
    des_key = get_random_bytes(8)
    des_iv = get_random_bytes(8)  # DES uses 8-byte IV
    print("\n--- DES Encryption ---")
    for message in messages:
        des_ciphertext = encrypt_des(des_key, des_iv, message)
        print(f"Message: {message} -> Encrypted: {des_ciphertext.hex()}")

    # AES-128 (16 bytes key), AES-192 (24 bytes key), AES-256 (32 bytes key)
    aes_keys = {
        'AES-128': get_random_bytes(16),  # 128 bits = 16 bytes
        'AES-192': get_random_bytes(24),  # 192 bits = 24 bytes
        'AES-256': get_random_bytes(32)   # 256 bits = 32 bytes
    }
    aes_iv = get_random_bytes(16)  # AES uses 16-byte IV

    for aes_key_type, aes_key in aes_keys.items():
        print(f"\n--- {aes_key_type} Encryption ---")
        for message in messages:
            aes_ciphertext = encrypt_aes(aes_key, aes_iv, message)
            print(f"Message: {message} -> Encrypted: {aes_ciphertext.hex()}")

if __name__ == "__main__":
    main()
