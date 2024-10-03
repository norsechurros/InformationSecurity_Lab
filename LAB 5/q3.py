import hashlib
import random
import string
import time
from collections import defaultdict

def generate_random_string(length):
    """Generate a random string of specified length."""
    characters = string.ascii_letters + string.digits + string.punctuation + ' '
    return ''.join(random.choice(characters) for _ in range(length))

def generate_dataset(num_strings, min_length=20, max_length=100):
    """Generate a dataset of random strings."""
    dataset = []
    for _ in range(num_strings):
        length = random.randint(min_length, max_length)
        random_str = generate_random_string(length)
        dataset.append(random_str)
    return dataset

def compute_hashes(dataset, hash_func_name):
    """Compute hashes for the dataset using the specified hash function."""
    hash_func = getattr(hashlib, hash_func_name)
    hashes = []
    start_time = time.perf_counter()
    for data in dataset:
        hash_object = hash_func()
        hash_object.update(data.encode('utf-8'))
        hash_digest = hash_object.hexdigest()
        hashes.append(hash_digest)
    end_time = time.perf_counter()
    computation_time = end_time - start_time
    return hashes, computation_time

def detect_collisions(hashes):
    """Detect collisions in the list of hashes."""
    hash_counts = defaultdict(int)
    for h in hashes:
        hash_counts[h] += 1
    collisions = {h: count for h, count in hash_counts.items() if count > 1}
    return collisions

def main():
    # Configuration
    NUM_STRINGS = 100  # Number of random strings in the dataset (50-100)
    MIN_LENGTH = 20    # Minimum length of each string
    MAX_LENGTH = 100   # Maximum length of each string

    # Generate dataset
    print("Generating dataset of random strings...")
    dataset = generate_dataset(NUM_STRINGS, MIN_LENGTH, MAX_LENGTH)
    print(f"Generated {len(dataset)} random strings.\n")

    # Define hashing algorithms to test
    hashing_algorithms = ['md5', 'sha1', 'sha256']

    # Store results
    results = {}

    for algo in hashing_algorithms:
        print(f"Computing hashes using {algo.upper()}...")
        hashes, comp_time = compute_hashes(dataset, algo)
        collisions = detect_collisions(hashes)
        results[algo] = {
            'hashes': hashes,
            'time': comp_time,
            'collisions': collisions
        }
        print(f"Time taken for {algo.upper()}: {comp_time:.6f} seconds")
        if collisions:
            print(f"Collisions detected in {algo.upper()}:")
            for h, count in collisions.items():
                print(f"  Hash: {h} | Count: {count}")
        else:
            print(f"No collisions detected in {algo.upper()}.")
        print()

    # Summary
    print("=== Summary ===")
    for algo in hashing_algorithms:
        time_taken = results[algo]['time']
        num_collisions = len(results[algo]['collisions'])
        collision_status = "Collisions found" if num_collisions > 0 else "No collisions"
        print(f"{algo.upper():<6} | Time: {time_taken:.6f} seconds | {collision_status}")

if __name__ == "__main__":
    main()
