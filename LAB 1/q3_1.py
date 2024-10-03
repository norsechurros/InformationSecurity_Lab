def generate_playfair_matrix(key):
    key = "".join(sorted(set(key), key=lambda x: key.index(x))).upper()
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No 'J' as Playfair combines I and J
    key = key.replace("J", "")
    remaining_chars = "".join([ch for ch in alphabet if ch not in key])
    full_key = key + remaining_chars
    matrix = [list(full_key[i * 5:(i + 1) * 5]) for i in range(5)]
    
    print("Generated Playfair Matrix:")
    for row in matrix:
        print(" ".join(row))
    print()
    
    return matrix

def prepare_message(message):
    message = message.upper().replace(" ", "")
    message = message.replace("J", "I")  # Replace 'J' with 'I' as per Playfair rules
    pairs = []
    i = 0
    while i < len(message):
        a = message[i]
        b = message[i+1] if i+1 < len(message) else 'X'
        if a == b:
            pairs.append(a + 'X')  # Insert 'X' if two consecutive letters are the same
            i += 1
        else:
            pairs.append(a + b)
            i += 2

    print(f"Prepared Message Pairs: {pairs}")
    return pairs

def find_position(matrix, letter):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None

def encipher_pair(matrix, pair):
    row1, col1 = find_position(matrix, pair[0])
    row2, col2 = find_position(matrix, pair[1])
    
    # Same row
    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    
    # Same column
    elif col1 == col2:
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    
    # Rectangle case
    else:
        return matrix[row1][col2] + matrix[row2][col1]

def encipher_message(matrix, pairs):
    ciphertext = ""
    for pair in pairs:
        ciphertext += encipher_pair(matrix, pair)
    print(f"Ciphertext: {ciphertext}")
    return ciphertext

# Example usage
key = "GUIDANCE"
message = "The key is hidden under the door pad"

# Generate matrix from key
matrix = generate_playfair_matrix(key)

# Prepare the message by converting it into pairs
pairs = prepare_message(message)

# Encipher the message using the Playfair matrix and prepared pairs
ciphertext = encipher_message(matrix, pairs)
