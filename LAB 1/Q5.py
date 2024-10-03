def determine_shift(ciphertext, plaintext):
    # Calculate the shift based on the first letter of ciphertext and plaintext
    shift = (ord(ciphertext[0]) - ord(plaintext[0])) % 26
    return shift

def decrypt_caesar_cipher(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Handle uppercase letters
            if char.isupper():
                new_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            # Handle lowercase letters
            else:
                new_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            plaintext += new_char
        else:
            # Include non-alphabet characters as is
            plaintext += char
    return plaintext

# Given values
known_ciphertext = "CIW"
known_plaintext = "yes"
new_ciphertext = "XVIEWYWI"

# Determine the shift value
shift = determine_shift(known_ciphertext, known_plaintext.lower())
print(f"Determined shift: {shift}")

# Decrypt the new ciphertext
decrypted_message = decrypt_caesar_cipher(new_ciphertext, shift)
print(f"Decrypted message: {decrypted_message}")
