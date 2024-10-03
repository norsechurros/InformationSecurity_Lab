from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import time

# Step 1: Key Generation for RSA and ECC
def generate_rsa_key(bits=2048):
    start_time = time.time()
    rsa_key = RSA.generate(bits)
    end_time = time.time()
    key_gen_time = end_time - start_time
    return rsa_key, key_gen_time

def generate_ecc_key(curve='P-256'):
    start_time = time.time()
    ecc_key = ECC.generate(curve=curve)
    end_time = time.time()
    key_gen_time = end_time - start_time
    return ecc_key, key_gen_time

# Step 2: AES Encryption and Decryption
def aes_encrypt(file_data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Step 3: RSA Encryption/Decryption of AES key
def rsa_encrypt_aes_key(aes_key, rsa_public_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    return cipher_rsa.encrypt(aes_key)

def rsa_decrypt_aes_key(encrypted_aes_key, rsa_private_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    return cipher_rsa.decrypt(encrypted_aes_key)

# Step 4: ECC Encryption/Decryption (Signing & Verifying the AES Key)
def ecc_sign_aes_key(aes_key, ecc_private_key):
    signer = DSS.new(ecc_private_key, 'fips-186-3')
    h = SHA256.new(aes_key)
    return signer.sign(h)

def ecc_verify_aes_key(aes_key, signature, ecc_public_key):
    verifier = DSS.new(ecc_public_key, 'fips-186-3')
    h = SHA256.new(aes_key)
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

# Step 5: Secure File Transfer
def secure_file_transfer_rsa(file_data, rsa_keypair):
    # Generate AES key
    aes_key = get_random_bytes(32)

    # Encrypt the file with AES
    nonce, ciphertext, tag = aes_encrypt(file_data, aes_key)

    # Encrypt the AES key with RSA
    encrypted_aes_key = rsa_encrypt_aes_key(aes_key, rsa_keypair.publickey())

    # Decrypt the AES key with RSA
    decrypted_aes_key = rsa_decrypt_aes_key(encrypted_aes_key, rsa_keypair)

    # Decrypt the file with AES
    decrypted_file_data = aes_decrypt(nonce, ciphertext, tag, decrypted_aes_key)
    
    return decrypted_file_data

def secure_file_transfer_ecc(file_data, ecc_keypair):
    # Generate AES key
    aes_key = get_random_bytes(32)

    # Encrypt the file with AES
    nonce, ciphertext, tag = aes_encrypt(file_data, aes_key)

    # Sign the AES key with ECC
    signature = ecc_sign_aes_key(aes_key, ecc_keypair)

    # Verify the AES key with ECC
    is_verified = ecc_verify_aes_key(aes_key, signature, ecc_keypair.public_key())

    if not is_verified:
        raise ValueError("AES key verification failed with ECC!")

    # Since ECC is used for signing, AES key is shared separately (similar to public key exchange)
    decrypted_file_data = aes_decrypt(nonce, ciphertext, tag, aes_key)
    
    return decrypted_file_data

# Performance measurement and comparison
def performance_test(file_size_mb):
    file_data = get_random_bytes(file_size_mb * 1024 * 1024)  # Generate random file data

    # RSA 2048-bit Test
    rsa_keypair, rsa_keygen_time = generate_rsa_key()
    start_time = time.time()
    rsa_decrypted_data = secure_file_transfer_rsa(file_data, rsa_keypair)
    rsa_transfer_time = time.time() - start_time

    # ECC (secp256r1) Test
    ecc_keypair, ecc_keygen_time = generate_ecc_key()
    start_time = time.time()
    ecc_decrypted_data = secure_file_transfer_ecc(file_data, ecc_keypair)
    ecc_transfer_time = time.time() - start_time

    # Verify results
    assert file_data == rsa_decrypted_data, "RSA Decryption failed!"
    assert file_data == ecc_decrypted_data, "ECC Decryption failed!"

    # Print performance results
    print(f"File Size: {file_size_mb} MB")
    print(f"RSA Key Generation Time: {rsa_keygen_time:.4f} seconds")
    print(f"RSA Transfer Time: {rsa_transfer_time:.4f} seconds")
    print(f"ECC Key Generation Time: {ecc_keygen_time:.4f} seconds")
    print(f"ECC Transfer Time: {ecc_transfer_time:.4f} seconds")
    print("-" * 50)

if __name__ == "__main__":
    performance_test(1)  # Test with 1 MB file
    performance_test(10)  # Test with 10 MB file
