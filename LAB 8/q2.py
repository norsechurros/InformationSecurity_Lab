import random
import math
from collections import defaultdict

# Utility function to calculate the Least Common Multiple (LCM)
def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

# Utility function to calculate the modular inverse using Extended Euclidean Algorithm
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# Extended Euclidean Algorithm to find gcd and the coefficients
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# Random prime number generation
def random_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if is_prime(prime_candidate):
            return prime_candidate

# A simple primality test using Miller-Rabin
def is_prime(n, k=5):  # number of tests
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Paillier key generation
def generate_paillier_keypair(bits=512):
    # Step 1: Generate two large prime numbers p and q
    p = random_prime(bits)
    q = random_prime(bits)
    
    # Step 2: Compute n = p * q
    n = p * q
    
    # Step 3: Compute lambda = lcm(p-1, q-1)
    lam = lcm(p-1, q-1)
    
    # Step 4: Choose g, typically g = n + 1
    g = n + 1
    
    # Step 5: Compute mu = (L(g^lambda mod n^2))^-1 mod n
    nsq = n * n  # n^2
    x = pow(g, lam, nsq)
    L_x = (x - 1) // n
    mu = modinv(L_x, n)
    
    # Public key is (n, g)
    public_key = (n, g)
    
    # Private key is (lambda, mu)
    private_key = (lam, mu)
    
    return public_key, private_key

# Paillier encryption
def paillier_encrypt(m, public_key):
    n, g = public_key
    nsq = n * n
    # Step 1: Pick a random number r where 1 <= r < n
    r = random.randint(1, n-1)
    
    # Step 2: Compute c = (g^m * r^n) mod n^2
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

# Paillier decryption
def paillier_decrypt(c, private_key, public_key):
    n, g = public_key
    lam, mu = private_key
    nsq = n * n
    
    # Step 1: Compute L(c^lambda mod n^2)
    x = pow(c, lam, nsq)
    L_x = (x - 1) // n
    
    # Step 2: Compute m = (L_x * mu) mod n
    m = (L_x * mu) % n
    return m

# Create the dataset (document IDs)
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

# Create an inverted index (word -> document IDs)
inverted_index = defaultdict(list)

for doc_id, document in zip(document_ids, documents):
    words = document.lower().split()
    for word in set(words):
        inverted_index[word].append(doc_id)

# Generate Paillier keypair
public_key, private_key = generate_paillier_keypair()

# Encrypt the inverted index (document IDs encrypted)
encrypted_inverted_index = {
    word: [paillier_encrypt(doc_id, public_key) for doc_id in doc_ids]
    for word, doc_ids in inverted_index.items()
}

# Search function
def search(query, encrypted_index, public_key, private_key):
    # Convert query to lowercase to match
    query = query.lower()

    if query in encrypted_index:
        # Decrypt the document IDs
        encrypted_doc_ids = encrypted_index[query]
        decrypted_doc_ids = [paillier_decrypt(enc_doc_id, private_key, public_key) for enc_doc_id in encrypted_doc_ids]

        # Retrieve the documents based on decrypted document IDs
        results = [documents[doc_id - 1] for doc_id in decrypted_doc_ids]
        return results
    else:
        return []

# Example search query
query = "fear"
results = search(query, encrypted_inverted_index, public_key, private_key)

# Output the search results
if results:
    print(f"Documents containing the word '{query}':")
    for result in results:
        print(result)
else:
    print(f"No documents found containing the word '{query}'.")
