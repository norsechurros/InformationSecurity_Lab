import random
import math

class Paillier:
    def __init__(self, bit_length=1024):
        self.bit_length = bit_length
        self.keygen()

    def keygen(self):
        """Generates a public and private key pair"""
        p = self.generate_large_prime(self.bit_length // 2)
        q = self.generate_large_prime(self.bit_length // 2)
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.lambda_val = self.lcm(p - 1, q - 1)
        self.mu = self.modinv(self.l_function(pow(self.g, self.lambda_val, self.n_sq)), self.n)

    def generate_large_prime(self, bit_length):
        """Generates a large prime number of bit_length bits"""
        while True:
            prime_candidate = random.getrandbits(bit_length)
            if self.is_prime(prime_candidate):
                return prime_candidate

    def is_prime(self, n, k=40):
        """Performs Miller-Rabin primality test to determine if n is prime"""
        if n <= 1:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randint(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def lcm(self, x, y):
        """Computes the least common multiple of x and y"""
        return abs(x * y) // math.gcd(x, y)

    def modinv(self, a, m):
        """Computes the modular inverse of a mod m"""
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return x % m

    def egcd(self, a, b):
        """Extended Euclidean Algorithm"""
        if a == 0:
            return b, 0, 1
        g, x, y = self.egcd(b % a, a)
        return g, y - (b // a) * x, x

    def l_function(self, x):
        """Paillier L function"""
        return (x - 1) // self.n

    def encrypt(self, plaintext):
        """Encrypts the plaintext"""
        r = random.randint(1, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        c = (pow(self.g, plaintext, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return c

    def decrypt(self, ciphertext):
        """Decrypts the ciphertext"""
        x = pow(ciphertext, self.lambda_val, self.n_sq)
        plaintext = (self.l_function(x) * self.mu) % self.n
        return plaintext

    def homomorphic_add(self, c1, c2):
        """Performs homomorphic addition of two ciphertexts"""
        return (c1 * c2) % self.n_sq

# Instantiate Paillier cryptosystem
paillier = Paillier()

# Encrypt two integers
plaintext1 = 15
plaintext2 = 25

ciphertext1 = paillier.encrypt(plaintext1)
ciphertext2 = paillier.encrypt(plaintext2)

print(f"Ciphertext of {plaintext1}: {ciphertext1}")
print(f"Ciphertext of {plaintext2}: {ciphertext2}")

# Perform homomorphic addition
ciphertext_sum = paillier.homomorphic_add(ciphertext1, ciphertext2)

print(f"Ciphertext of {plaintext1} + {plaintext2}: {ciphertext_sum}")

# Decrypt the result of the homomorphic addition
decrypted_sum = paillier.decrypt(ciphertext_sum)

print(f"Decrypted sum: {decrypted_sum}")
