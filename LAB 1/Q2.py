# Vigenère Cipher Encryption
def vignere_encrypt(plaintext, keyword):
    keyword = keyword.lower()
    cipher = ""
    keyword_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(keyword[keyword_index]) - ord('a')  # Compute shift from keyword
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            elif char.isupper():
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            keyword_index = (keyword_index + 1) % len(keyword)  # Move to the next character in the keyword
        else:
            encrypted_char = char  # Non-alphabetic characters are kept unchanged
        cipher += encrypted_char

    print("Vigenère Ciphertext: ", cipher)
    return cipher

# Vigenère Cipher Decryption
def vignere_decrypt(ciphertext, keyword):
    keyword = keyword.lower()
    plaintext = ""
    keyword_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(keyword[keyword_index]) - ord('a')
            if char.islower():
                decrypted_char = chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a'))
            elif char.isupper():
                decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            keyword_index = (keyword_index + 1) % len(keyword)
        else:
            decrypted_char = char
        plaintext += decrypted_char

    print("Vigenère Decrypted Plaintext: ", plaintext)
    return plaintext

# Autokey Cipher Encryption
def autokey_encrypt(plaintext, key):
    cipher = ''
    prev_char = chr(key + ord('a'))  # Initialize the first character's shift with the key

    for char in plaintext:
        if char.isalpha():
            if char.islower():
                shift = ord(prev_char) - ord('a')
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            elif char.isupper():
                shift = ord(prev_char) - ord('A')
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            prev_char = char  # Update previous character to current one
        else:
            encrypted_char = char
        cipher += encrypted_char

    print("Autokey Ciphertext: ", cipher)
    return cipher

# Autokey Cipher Decryption
def autokey_decrypt(ciphertext, key):
    plaintext = ''
    prev_char = chr(key + ord('a'))  # Initialize with the key

    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                shift = ord(prev_char) - ord('a')
                decrypted_char = chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a'))
            elif char.isupper():
                shift = ord(prev_char) - ord('A')
                decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            prev_char = decrypted_char  # Update the previous character to the decrypted one
        else:
            decrypted_char = char
        plaintext += decrypted_char

    print("Autokey Decrypted Plaintext: ", plaintext)
    return plaintext

# Example usage
plaintext_vigenere = "hello world"
keyword = "key"

# Vigenère Encryption
vigenere_ciphertext = vignere_encrypt(plaintext_vigenere, keyword)

# Vigenère Decryption
vigenere_decrypted = vignere_decrypt(vigenere_ciphertext, keyword)


plaintext_autokey = "attack is today"
key_autokey = 12

# Autokey Encryption
autokey_ciphertext = autokey_encrypt(plaintext_autokey, key_autokey)

# Autokey Decryption
autokey_decrypted = autokey_decrypt(autokey_ciphertext, key_autokey)
