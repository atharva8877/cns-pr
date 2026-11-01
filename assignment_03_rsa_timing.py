"""Assignment 3: textbook RSA timing demo.

This program generates RSA keys, encrypts and decrypts a user-provided message,
measures the time taken for key generation, encryption, and decryption, and
prints the results in a lab-friendly format.
"""

import math
import secrets
import time


PUBLIC_EXPONENT = 65537


def is_probable_prime(number, rounds=16):
    """Miller-Rabin primality test for a small classroom RSA demo."""
    if number < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if number == prime:
            return True
        if number % prime == 0:
            return False

    odd_part = number - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        powers_of_two += 1

    for _ in range(rounds):
        base = secrets.randbelow(number - 3) + 2
        value = pow(base, odd_part, number)
        if value in (1, number - 1):
            continue
        for _ in range(powers_of_two - 1):
            value = pow(value, 2, number)
            if value == number - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """Generate an odd probable prime with exactly the required bit length."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate) and math.gcd(candidate - 1, PUBLIC_EXPONENT) == 1:
            return candidate


def generate_rsa_keypair(bits):
    """Create the public and private RSA key pair."""
    if bits < 32:
        raise ValueError("Use a key size of at least 32 bits for the demo.")

    p = generate_prime(bits // 2)
    q = generate_prime(bits - bits // 2)
    while p == q:
        q = generate_prime(bits - bits // 2)

    modulus = p * q
    totient = (p - 1) * (q - 1)
    private_exponent = pow(PUBLIC_EXPONENT, -1, totient)
    return (modulus, PUBLIC_EXPONENT), (modulus, private_exponent)


def benchmark(message_text, key_sizes=(512, 1024, 2048)):
    """Generate keys and time RSA encryption and decryption for a message."""
    message_bytes = message_text.encode("utf-8")
    message_int = int.from_bytes(message_bytes, byteorder="big")

    for bits in key_sizes:
        start = time.perf_counter()
        public_key, private_key = generate_rsa_keypair(bits)
        keygen_seconds = time.perf_counter() - start

        modulus, exponent = public_key
        _, private_exponent = private_key

        if message_int >= modulus:
            raise ValueError("Message must be smaller than the modulus for textbook RSA.")

        encrypt_start = time.perf_counter()
        encrypted_int = pow(message_int, exponent, modulus)
        encrypt_seconds = time.perf_counter() - encrypt_start

        decrypt_start = time.perf_counter()
        decrypted_int = pow(encrypted_int, private_exponent, modulus)
        decrypt_seconds = time.perf_counter() - decrypt_start

        if decrypted_int != message_int:
            raise RuntimeError("RSA round-trip verification failed.")

        encrypted_bytes = encrypted_int.to_bytes((modulus.bit_length() + 7) // 8, byteorder="big")
        decrypted_bytes = decrypted_int.to_bytes(len(message_bytes), byteorder="big")

        print(f"RSA Key Size: {bits} bits")
        print(f"Original Message : {message_text}")
        print(f"Encrypted Message: {encrypted_bytes!r}")
        print(f"Decrypted Message: {decrypted_bytes.decode('utf-8', errors='replace')}")
        print("Time Required")
        print(f"Key Generation : {keygen_seconds:.6f} seconds")
        print(f"Encryption     : {encrypt_seconds:.6f} seconds")
        print(f"Decryption     : {decrypt_seconds:.6f} seconds")
        print()


if __name__ == "__main__":
    message = input("Enter the message: ")
    benchmark(message)
