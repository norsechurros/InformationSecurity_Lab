def additive_encrypt(s, k):
    cipher = ""
    for i in s:
        if i.isalpha():
            inAlpha = ord(i) + k
            if i.islower() and inAlpha > ord('z'):
                inAlpha -= 26
            elif i.isupper() and inAlpha > ord('Z'):
                inAlpha -= 26
            fin = chr(inAlpha)
        else:
            fin = i
        cipher += fin
    print("Additive Encryption Ciphertext: ", cipher)
    return cipher

def additive_decrypt(s, k):
    cipher = ""
    for i in s:
        if i.isalpha():
            inAlpha = ord(i) - k  # Subtract key for decryption
            if i.islower() and inAlpha < ord('a'):
                inAlpha += 26  # Wrap around for lowercase
            elif i.isupper() and inAlpha < ord('A'):
                inAlpha += 26  # Wrap around for uppercase
            fin = chr(inAlpha)
        else:
            fin = i
        cipher += fin
    print("Additive Decryption Plaintext: ", cipher)
    return cipher

def multiplicative_encrypt(s, k):
    cipher = ""
    for i in s:
        if i.isalpha():
            if i.islower():
                inAlpha = ((ord(i) - ord('a')) * k) % 26 + ord('a')
            elif i.isupper():
                inAlpha = ((ord(i) - ord('A')) * k) % 26 + ord('A')
            fin = chr(inAlpha)
        else:
            fin = i
        cipher += fin
    print("Multiplicative Encryption Ciphertext: ", cipher)
    return cipher

def multiplicative_decrypt(s, k):
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None
    
    m = 26
    inv_k = mod_inverse(k, m)
    if inv_k is None:
        raise ValueError("No modular inverse for k. k and m must be coprime.")
    return multiplicative_encrypt(s, inv_k)

def affine_encrypt(s, a, b):
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    m = 26
    if mod_inverse(a, m) is None:
        raise ValueError("a and m must be coprime.")
    cipher = ""
    
    for i in s:
        if i.isalpha():
            if i.islower():
                x = ord(i) - ord('a')
                inAlpha = (a * x + b) % m + ord('a')
            elif i.isupper():
                x = ord(i) - ord('A')
                inAlpha = (a * x + b) % m + ord('A')
            fin = chr(inAlpha)
        else:
            fin = i
        cipher += fin
    print("Affine Encryption Ciphertext: ", cipher)
    return cipher

def affine_decrypt(s, a, b):
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    m = 26
    a_inv = mod_inverse(a, m)
    if a_inv is None:
        raise ValueError("a and m must be coprime.")
    
    cipher = ""
    for i in s:
        if i.isalpha():
            if i.islower():
                y = ord(i) - ord('a')
                x = (a_inv * (y - b)) % m
                inAlpha = x + ord('a')
            elif i.isupper():
                y = ord(i) - ord('A')
                x = (a_inv * (y - b)) % m
                inAlpha = x + ord('A')
            fin = chr(inAlpha)
        else:
            fin = i
        cipher += fin
    print("Affine Decryption Plaintext: ", cipher)
    return cipher

# Example usage
message = "I am learning information security"
additive_key = 20
multiplicative_key = 15
affine_a = 15
affine_b = 20

# Encryption
additive_ciphertext = additive_encrypt(message, additive_key)
multiplicative_ciphertext = multiplicative_encrypt(message, multiplicative_key)
affine_ciphertext = affine_encrypt(message, affine_a, affine_b)

# Decryption
additive_plaintext = additive_decrypt(additive_ciphertext, additive_key)
multiplicative_plaintext = multiplicative_decrypt(multiplicative_ciphertext, multiplicative_key)
affine_plaintext = affine_decrypt(affine_ciphertext, affine_a, affine_b)
