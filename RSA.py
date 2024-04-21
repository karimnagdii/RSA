import math
import random
import time


def is_prime(n, k=5):
    """
    Check if a number is prime using Miller-Rabin primality test.

    Args:
        n (int): The number to check for primality.
        k (int): The number of iterations for the Miller-Rabin test. Default is 5.

    Returns:
        bool: True if n is prime, False otherwise.
    """
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    def check_composite(a, d, s, n):
        """
        Check if a number is composite using the Miller-Rabin test.

        Args:
            a (int): The random base for the test.
            d (int): The exponent of the power.
            s (int): The number of times to apply the power.
            n (int): The number to check for primality.

        Returns:
            bool: True if n is composite, False otherwise.
        """
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return False
        return True

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 1)
        if check_composite(a, d, s, n):
            return False
    return True


def generate_random_prime(bits):
    """
    Generate a random prime number of specified bits.

    Args:
        bits (int): The number of bits for the random prime number.

    Returns:
        int: A randomly generated prime number.
    """
    while True:
        candidate = random.getrandbits(bits)
        if is_prime(candidate):
            return candidate


def gcd_extended(a, b):
    """
    Extended Euclidean Algorithm to find gcd and coefficients.

    Args:
        a (int): The first integer.
        b (int): The second integer.

    Returns:
        tuple: A tuple containing gcd and coefficients (gcd, x, y).
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def modular_inverse(e, phi):
    """
    Calculate modular inverse using Extended Euclidean Algorithm.

    Args:
        e (int): The exponent.
        phi (int): Euler's totient function value.

    Returns:
        int: The modular inverse of e modulo phi.

    Raises:
        ValueError: If modular inverse does not exist.
    """
    gcd, x, _ = gcd_extended(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi


def generate_rsa_key(bits):
    """
    Generate RSA public and private key pairs.

    Args:
        bits (int): The number of bits for the RSA key.

    Returns:
        tuple: A tuple containing the public and private keys (public_key, private_key).
    """
    while True:
        p = generate_random_prime(bits // 2)
        q = generate_random_prime(bits // 2)
        while p == q:  # Ensure p and q are distinct
            q = generate_random_prime(bits // 2)

        N = p * q
        phi = (p - 1) * (q - 1)

        if phi <= 1:
            continue

        common_e_values = [3, 17, 65537]

        for e in common_e_values:
            if math.gcd(e, phi) == 1:
                d = modular_inverse(e, phi)
                public_key = (N, e)
                private_key = (N, d)
                return public_key, private_key


def factorization_with_phi(N):
    """
    Factorization method to break RSA key.

    Args:
        N (int): The RSA modulus.

    Returns:
        tuple or None: A tuple containing factors (p, q) and phi if successful, otherwise None.
    """
    for i in range(2, math.isqrt(N) + 1):
        if N % i == 0:
            if is_prime(i) and is_prime(N // i):
                p, q = i, N // i
                phi = (p - 1) * (q - 1)
                return p, q, phi
    return None


def brute_force_private_exponent(public_key, p, q):
    """
    Brute-force method to break RSA key.

    Args:
        public_key (tuple): A tuple containing the RSA public key (N, e).
        p (int): One prime factor of N.
        q (int): Another prime factor of N.

    Returns:
        int or None: The private exponent if successful, otherwise None.
    """
    N, e = public_key

    # Limiting the search space for d to be less than N
    d = 2
    while d < N:
        # Check if d is the correct private exponent
        if (e * d) % ((p - 1) * (q - 1)) == 1:
            return d
        d += 1

    # If no valid private exponent is found
    return None


def main():
    """
    Main function to demonstrate RSA key generation and breaking methods.
    """
    bits_list = [8, 16]  # Sizes of RSA key

    for bits in bits_list:
        print(f"Generating RSA Key Pair for {bits}-bit RSA:")
        for _ in range(4):
            public_key, private_key = generate_rsa_key(bits)
            print("\nGenerated RSA Key Pair:")
            print(f"Key size: {bits} bits")
            print("Public Key (N, e):", public_key)
            print("Private Key (N, d):", private_key)
            print()

            print("Breaking RSA Key using Factorization Method:")
            start_time = time.time()
            factors = factorization_with_phi(public_key[0])
            end_time = time.time()
            if factors:
                p, q, phi = factors
                d = modular_inverse(public_key[1], phi)
                print("RSA Key successfully broken using factorization!")
                print("Factors (p, q):", p, q)
                print("Private Exponent (d):", d)
                print("Runtime:", end_time - start_time, "seconds")
            else:
                print("Factorization method failed.")
                print("Runtime:", end_time - start_time, "seconds")

            # Try to break the key using brute-force method
            print("\nBreaking RSA Key using Brute-Force Method:")
            start_time = time.time()
            if factors:
                p, q, phi = factors
                d = brute_force_private_exponent(public_key, p, q)
                if d is not None:
                    print("RSA Key successfully broken using brute-force!")
                    print("Private Exponent (d):", d)
                else:
                    print("Brute-force method failed.")
            else:
                print("Factorization failed, cannot proceed with brute-force method.")
            print("Runtime:", time.time() - start_time, "seconds")
            print("-" * 50)
            print()


if __name__ == "__main__":
    main()
