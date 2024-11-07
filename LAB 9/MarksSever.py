import socket
from Crypto.Util.number import getPrime, inverse, GCD
from hashlib import sha256
import pickle

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, y, x = extended_gcd(b % a, a)
        return gcd, x - (b // a) * y, y

def generate_rabin_key(bits):
    # p and q need to be primes congruent to 3 mod 4
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(bits)
        if q % 4 == 3 and q != p:
            break
    n = p * q
    return (n, p, q)

def rabin_decrypt(c, p, q):
    # Compute square roots modulo p and q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    # Use the extended Euclidean algorithm to find coefficients
    gcd, yp, yq = extended_gcd(p, q)
    # Combine solutions using the Chinese Remainder Theorem
    n = p * q
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3
    return [r1, r2, r3, r4]

def elgamal_verify(m_hash_int, signature, p, g, y):
    r, s = signature
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m_hash_int, p)
    return v1 == v2

def main():
    # Generate Rabin keys
    n_bits = 256  # Small size for demonstration
    n, p_rabin, q_rabin = generate_rabin_key(n_bits)
    print(f"\nRabin public key (n): {n}")
    print(f"Rabin private keys (p, q):\n p = {p_rabin}\n q = {q_rabin}")

    # Start server
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('localhost', 12345))
    s.listen(5)
    print("\nServer is listening on port 12345...")

    while True:
        conn, addr = s.accept()
        print(f"\nConnected by {addr}")
        data = conn.recv(4096)
        if not data:
            conn.close()
            continue
        if data == b'get_rabin_public_key':
            # Send Rabin public key n to client
            conn.sendall(str(n).encode())
            conn.close()
            print("Sent Rabin public key to client.")
            continue
        else:
            # Assume the data is pickled data sent from the client
            received_data = pickle.loads(data)
            # Process received data
            name = received_data['name']
            ciphertext = received_data['ciphertext']
            client_hash = received_data['hash']
            signature = received_data['signature']
            elgamal_public_key = received_data['elgamal_public_key']
            p_elgamal, g_elgamal, y_elgamal = elgamal_public_key

            print(f"\nReceived data from client '{name}':")
            print(f"Ciphertext: {ciphertext}")
            print(f"Client's hash: {client_hash}")
            print(f"ElGamal signature (r, s): {signature}")
            print(f"ElGamal public key (p, g, y):\n p = {p_elgamal}\n g = {g_elgamal}\n y = {y_elgamal}")

            # Decrypt the ciphertext
            possible_marks = rabin_decrypt(ciphertext, p_rabin, q_rabin)
            print(f"\nPossible decrypted marks: {possible_marks}")
            # Need to select the correct plaintext
            # Assume marks are between 0 and 100
            marks = None
            for m in possible_marks:
                if 0 <= m <= 100:
                    marks = m
                    break
            if marks is None:
                print("Correct plaintext not found among possible plaintexts.")
                conn.close()
                continue
            print(f"Decrypted marks: {marks}")

            # Hash the marks
            message = str(marks)
            hash_obj = sha256(message.encode())
            server_hash = hash_obj.hexdigest()
            print(f"\nServer's computed hash: {server_hash}")

            # Verify the hash matches client's hash
            if server_hash == client_hash:
                print("Hashes match. No tampering detected.")
            else:
                print("Hashes do not match. Data may have been tampered with.")

            # Verify the digital signature
            m_hash_int = int(server_hash, 16)
            is_valid_signature = elgamal_verify(m_hash_int, signature, p_elgamal, g_elgamal, y_elgamal)
            if is_valid_signature:
                print("Digital signature verified successfully.")
            else:
                print("Digital signature verification failed.")
            conn.close()
            print("Processing complete.\n")

if __name__ == "__main__":
    main()
