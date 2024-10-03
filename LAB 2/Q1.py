from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify

# Original message
message = b"Confidential Data"

# DES key (must be 8 bytes long)
key = b"A1B2C3D4"  # Note: This is not a valid DES key due to length; adjust accordingly

# Create a DES cipher object
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt the message
ciphertext = cipher.encrypt(pad(message, DES.block_size))

print(f"Encrypted message: {hexlify(ciphertext).decode()}")

# Decrypt the ciphertext
cipher_dec = DES.new(key, DES.MODE_ECB)
decrypted_message = unpad(cipher_dec.decrypt(ciphertext), DES.block_size)

print(f"Decrypted message: {decrypted_message.decode()}")