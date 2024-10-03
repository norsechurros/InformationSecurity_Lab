def djb2_hash(input_string):
    """
    Implements the DJB2 hash algorithm with modifications as per the given specifications.
    
    :param input_string: The string to be hashed
    :return: A 32-bit integer representing the hash value
    """
    hash_value = 5381  # Initial hash value
    ascii_mask = 0xFF  # Mask for getting ASCII value
    
    for char in input_string:
        # Multiply current hash value by 33
        hash_value *= 33
        
        # Add ASCII value of the character
        hash_value += ord(char) & ascii_mask
        
        # Apply bitwise XOR to mix bits thoroughly
        hash_value ^= hash_value >> 16
    
    # Ensure hash value stays within 32-bit range
    hash_value &= 0xFFFFFFFF
    
    return hash_value

# Example usage
input_str = "Hello, World!"
hash_result = djb2_hash(input_str)
print(f"Hash of '{input_str}' is: {hash_result}")
print(f"Hex representation: 0x{hash_result:08X}")
