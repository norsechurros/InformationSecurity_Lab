def mod_inverse(a, m):
    # Find modular inverse of a under modulo m
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(ciphertext, a, b):
    m = 26
    a_inv = mod_inverse(a, m)
    if a_inv is None:
        return None  # No valid inverse, so this a is not valid

    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            x = ord(char.upper()) - ord('A')
            p = (a_inv * (x - b)) % m
            plaintext += chr(p + ord('A'))
        else:
            plaintext += char
    return plaintext

def brute_force_affine(ciphertext, known_plaintext):
    # Convert known plaintext and ciphertext to numerical values
    known_pt_nums = [ord(c) - ord('a') for c in known_plaintext]
    cipher_pt_nums = [ord(c) - ord('A') for c in ciphertext]
    
    for a in range(1, 26):
        if mod_inverse(a, 26) is None:
            continue  # Skip if a has no modular inverse
        
        for b in range(26):
            a1, b1 = known_pt_nums
            c1, c2 = cipher_pt_nums
            # Check if this a and b match the given pairs
            if (a * a1 + b) % 26 == c1 and (a * b1 + b) % 26 == c2:
                print(f"Possible key: a = {a}, b = {b}")
                decrypted_message = affine_decrypt(ciphertext, a, b)
                print(f"Decrypted message with a={a}, b={b}: {decrypted_message}")

# Known values
ciphertext = "GL"
known_plaintext = "ab"

# Run brute force attack
brute_force_affine(ciphertext, known_plaintext)
