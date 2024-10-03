import numpy as np

def hill(key, pt):
    
    n = 3
    
    # Construct the 3x3 matrix from the key
    matrix = [list(key[i*n:(i+1)*n]) for i in range(n)]
    
    print("Key Matrix:")
    for row in matrix:
        print(row)
        
    def char_to_num(c):
        return ord(c) - ord('A')
    
    def num_to_char(n):
        return chr(n + ord('A'))
    
    # Convert key matrix to numerical form
    key_matrix = np.array([[char_to_num(char) for char in row] for row in matrix])
    
    # Prepare the plaintext
    pt = pt.upper()
    pt_numbers = [char_to_num(c) for c in pt]
    
    # Encrypt the plaintext in blocks of size n
    ciphertext = ""
    for i in range(0, len(pt_numbers), n):
        pt_block = pt_numbers[i:i+n]
        if len(pt_block) < n:
            pt_block.extend([0] * (n - len(pt_block)))  # Padding if necessary
        
        pt_block = np.array(pt_block)
        cipher_block = np.dot(key_matrix, pt_block) % 26
        ciphertext += ''.join(num_to_char(num) for num in cipher_block)
    
    print("Ciphertext:")
    print(ciphertext)
        
hill("GYBNQKURP", "ACT")
