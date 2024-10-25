from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
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

# AES encryption and decryption functions
def encrypt(text, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

key = os.urandom(32)  # 256-bit key

# Create inverted index
inverted_index = defaultdict(list)
for doc_id, document in zip(document_ids, documents):
    words = document.lower().split()
    for word in set(words):
        inverted_index[word].append(doc_id)

# Encrypt the inverted index
encrypted_inverted_index = {word: encrypt(','.join(map(str, doc_ids)), key) for word, doc_ids in inverted_index.items()}

# Search function
def search(query, encrypted_index, key):
    encrypted_query = encrypt(query.lower(), key)
    decrypted_doc_ids = []

    for word in encrypted_index:
        if word == query.lower():
            encrypted_doc_ids = encrypted_index[word]
            decrypted_doc_ids = decrypt(encrypted_doc_ids, key).split(',')
            decrypted_doc_ids = [int(doc_id) for doc_id in decrypted_doc_ids]
            break

    results = [documents[doc_id - 1] for doc_id in decrypted_doc_ids] if decrypted_doc_ids else []
    return results

# Example query
query = "fear"
results = search(query, encrypted_inverted_index, key)
if results:
    print(f"Documents containing the word '{query}':")
    for result in results:
        print(result)
else:
    print(f"No documents found containing the word '{query}'.")
