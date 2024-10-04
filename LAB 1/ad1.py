def decrypt_additive_cipher(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():  # Decrypt only alphabetic characters
            # Handle both upper and lowercase letters
            shift = ord('A') if char.isupper() else ord('a')
            # Apply the shift
            decrypted_char = chr(((ord(char) - shift - key) % 26) + shift)
            plaintext += decrypted_char
        else:
            # Non-alphabetic characters are added as is
            plaintext += char
    return plaintext

def brute_force_attack(ciphertext):
    # Assuming Alice's key is close to 13, we will check keys from 1 to 25
    for key in range(1, 26):
        print(f"Key = {key}: {decrypt_additive_cipher(ciphertext, key)}")

# Ciphertext given by Alice
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Perform brute-force attack
brute_force_attack(ciphertext)
