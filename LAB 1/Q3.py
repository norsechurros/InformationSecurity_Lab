def generate_playfair_matrix(key):
    key = "".join(sorted(set(key), key=lambda x: key.index(x))).upper()
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = key.replace("J", "")
    remaining_chars = "".join([ch for ch in alphabet if ch not in key])
    full_key = key + remaining_chars
    matrix = [list(full_key[i*5:(i+1)*5]) for i in range(5)]
    return matrix

def prepare_message(message):
    message = message.upper().replace(" ", "")
    pairs = []
    i = 0
    while i < len(message):
        a = message[i]
        b = message[i+1] if i+1 < len(message) else 'X'
        if a == b:
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
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
    if row1 == row2:
        return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
    elif col1 == col2:
        return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]

def encipher_message(matrix, pairs):
    ciphertext = ""
    for pair in pairs:
        ciphertext += encipher_pair(matrix, pair)
    return ciphertext

matrix = generate_playfair_matrix("GUIDANCE")
pairs = prepare_message("The key is hidden under the door pad")
ciphertext = encipher_message(matrix, pairs)
print(ciphertext)
