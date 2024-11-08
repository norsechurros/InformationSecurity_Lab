from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from collections import defaultdict
import os

# Sample dataset: A list of documents
documents = [
    "The quick brown fox jumps over the lazy dog",
    "A journey of a thousand miles begins with a single step",
    "To be or not to be that is the question",
    "All that glitters is not gold",
    "I think therefore I am",
    "The only thing we have to fear is fear itself",
    "In the beginning was the Word and the Word was with God",
    "The pen is mightier than the sword",
    "The best way to predict the future is to invent it",
    "Do unto others as you would have them do unto you"
]
document_ids = list(range(1, len(documents) + 1))

# RSA key generation
def generate_rsa_keys(key_size=2048):
    print("Generating RSA key pair...")
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()
    print("RSA key pair generated.\n")
    return private_key, public_key

# RSA encryption and decryption functions (with padding)
def rsa_encrypt(public_key, plaintext):
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_v1_5.new(private_key)
    sentinel = None  # In practice, use a proper sentinel
    plaintext = cipher.decrypt(ciphertext, sentinel)
    if plaintext is None:
        raise ValueError("Decryption failed.")
    return plaintext.decode()

# SHA-256 hashing function
def sha256_hash(message):
    hash_obj = SHA256.new()
    hash_obj.update(message.encode())
    hash_value = hash_obj.digest()
    return hash_obj, hash_value

# RSA signing and verification functions
def rsa_sign(private_key, hash_obj):
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return signature

def rsa_verify(public_key, hash_obj, signature):
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

# Create inverted index
def create_inverted_index(documents, document_ids):
    inverted_index = defaultdict(list)
    for doc_id, document in zip(document_ids, documents):
        words = document.lower().split()
        for word in set(words):
            inverted_index[word].append(doc_id)
    return inverted_index

# Encrypt the inverted index
def encrypt_inverted_index(inverted_index, public_key):
    encrypted_inverted_index = {}
    for word, doc_ids in inverted_index.items():
        doc_ids_str = ','.join(map(str, doc_ids))
        ciphertext = rsa_encrypt(public_key, doc_ids_str)
        encrypted_inverted_index[word] = ciphertext
    return encrypted_inverted_index

# Decrypt the document IDs
def decrypt_doc_ids(private_key, ciphertext):
    decrypted_str = rsa_decrypt(private_key, ciphertext)
    doc_ids = list(map(int, decrypted_str.split(',')))
    return doc_ids

# Search function
def search(query, encrypted_index, private_key, public_key):
    query = query.lower()
    print(f"\nSearching for the word: '{query}'")
    
    if query in encrypted_index:
        ciphertext = encrypted_index[query]
        print(f"Ciphertext of document IDs for '{query}': {ciphertext.hex()}")
        
        # Decrypt document IDs
        try:
            doc_ids = decrypt_doc_ids(private_key, ciphertext)
            print(f"Decrypted document IDs for '{query}': {doc_ids}")
        except ValueError:
            print("Decryption failed. Possible tampering detected.")
            return None, None
        
        # Retrieve documents
        results = [documents[doc_id - 1] for doc_id in doc_ids]
        print(f"Documents containing '{query}':")
        for result in results:
            print(f"- {result}")
        
        # Hash the query
        hash_obj, hash_value = sha256_hash(query)
        print(f"\nSHA-256 Hash of query '{query}': {hash_value.hex()}")
        
        # Sign the hash
        signature = rsa_sign(private_key, hash_obj)
        print(f"RSA Signature of the hash: {signature.hex()}")
        
        # Verify the signature
        is_valid = rsa_verify(public_key, hash_obj, signature)
        print(f"Signature verification result: {'Valid' if is_valid else 'Invalid'}")
        
        return ciphertext, signature
    else:
        print(f"No documents found containing the word '{query}'.")
        return None, None

# Demonstrate homomorphic property of RSA
def demonstrate_homomorphic_property(public_key, private_key):
    print("\n--- Demonstrating RSA Homomorphic Property ---")
    m1 = 6
    m2 = 7
    print(f"Original messages: m1 = {m1}, m2 = {m2}")
    
    # Get RSA key parameters
    n = public_key.n
    e = public_key.e
    d = private_key.d
    
    print(f"RSA Modulus (n): {n}")
    print(f"RSA Public Exponent (e): {e}")
    print(f"RSA Private Exponent (d): {d}\n")
    
    # Encrypt messages manually: c = m^e mod n
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)
    print(f"Encrypted messages:")
    print(f"c1 (m1): {c1}")
    print(f"c2 (m2): {c2}")
    
    # Homomorphic operation: c1 * c2 mod n = E(m1 * m2 mod n)
    c_mul = (c1 * c2) % n
    print(f"\nHomomorphic operation (c1 * c2 mod n): {c_mul}")
    
    # Decrypt the result: m = c_mul^d mod n
    decrypted_mul = pow(c_mul, d, n)
    print(f"Decrypted result of homomorphic operation: {decrypted_mul}")
    
    # Expected result
    expected = (m1 * m2) % n
    print(f"Expected (m1 * m2) mod n: {expected}")
    
    if decrypted_mul == expected:
        print("Homomorphic property verified.")
    else:
        print("Homomorphic property verification failed.")

def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()
    
    # Create inverted index
    inverted_index = create_inverted_index(documents, document_ids)
    print("Inverted Index Created:")
    for word, ids in inverted_index.items():
        print(f"'{word}': {ids}")
    
    # Encrypt the inverted index
    encrypted_inverted_index = encrypt_inverted_index(inverted_index, public_key)
    print("\nEncrypted Inverted Index:")
    for word, ciphertext in encrypted_inverted_index.items():
        print(f"'{word}': {ciphertext.hex()}")
    
    # Example queries
    queries = ["fear", "the", "journey", "unknown"]
    
    for query in queries:
        search(query, encrypted_inverted_index, private_key, public_key)
    
    # Demonstrate homomorphic property
    demonstrate_homomorphic_property(public_key, private_key)

if __name__ == "__main__":
    main()
