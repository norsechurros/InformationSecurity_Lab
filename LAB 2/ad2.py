from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify, hexlify
from Crypto.Random import get_random_bytes

def des_encrypt(key, iv, data):
    des = DES.new(key, DES.MODE_CBC, iv)
    encrypted_data = des.encrypt(pad(data, DES.block_size))
    return encrypted_data

def des_decrypt(key, iv, encrypted_data):
    des = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = unpad(des.decrypt(encrypted_data), DES.block_size)
    return decrypted_data

def main():
    # Key and IV (Initialization Vector)
    key = unhexlify("A1B2C3D4E5F60708")  # Convert hex key to bytes
    iv = get_random_bytes(8)  # Generate a random IV for CBC mode
    
    # Block 1 data (in hex)
    block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
    block1_data = unhexlify(block1_hex)  # Convert hex string to bytes
    
    # Block 2 data (in hex)
    block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"
    block2_data = unhexlify(block2_hex)  # Convert hex string to bytes
    
    # Encrypt Block 1
    encrypted_block1 = des_encrypt(key, iv, block1_data)
    print(f"Encrypted Block 1 (Hex): {hexlify(encrypted_block1).decode()}")
    
    # Encrypt Block 2
    encrypted_block2 = des_encrypt(key, iv, block2_data)
    print(f"Encrypted Block 2 (Hex): {hexlify(encrypted_block2).decode()}")
    
    # Decrypt Block 1
    decrypted_block1 = des_decrypt(key, iv, encrypted_block1)
    print(f"Decrypted Block 1: {decrypted_block1.decode()}")
    
    # Decrypt Block 2
    decrypted_block2 = des_decrypt(key, iv, encrypted_block2)
    print(f"Decrypted Block 2: {decrypted_block2.decode()}")

if __name__ == "__main__":
    main()
