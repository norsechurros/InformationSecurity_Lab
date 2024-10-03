import random

# Diffie-Hellman Key Generation and Shared Secret Calculation
def diffie_hellman_key_exchange(p, g):
    # Alice generates her private key (a)
    a_private = random.randint(1, p - 2)
    # Alice calculates her public key (A = g^a mod p)
    A_public = pow(g, a_private, p)
    
    # Bob generates his private key (b)
    b_private = random.randint(1, p - 2)
    # Bob calculates his public key (B = g^b mod p)
    B_public = pow(g, b_private, p)
    
    # Alice calculates the shared secret (S = B^a mod p)
    alice_shared_secret = pow(B_public, a_private, p)
    
    # Bob calculates the shared secret (S = A^b mod p)
    bob_shared_secret = pow(A_public, b_private, p)
    
    return A_public, B_public, alice_shared_secret, bob_shared_secret

# Example usage
if __name__ == "__main__":
    # Prime number p and generator g (for real-world scenarios, use large secure primes)
    p = 23  # A small prime for example (in practice, use large primes like 2048-bit)
    g = 5   # A small generator (in practice, use a known generator)

    # Perform Diffie-Hellman key exchange
    A_public, B_public, alice_shared_secret, bob_shared_secret = diffie_hellman_key_exchange(p, g)
    
    # Display results
    print(f"Alice's Public Key: {A_public}")
    print(f"Bob's Public Key: {B_public}")
    print(f"Alice's Shared Secret: {alice_shared_secret}")
    print(f"Bob's Shared Secret: {bob_shared_secret}")

    # Verify if the shared secrets match
    if alice_shared_secret == bob_shared_secret:
        print("Shared secret successfully established!")
    else:
        print("Error in establishing shared secret.")
