"""Assignment 4: a reversible custom cipher for learning only.

This small Feistel construction demonstrates invertible encryption/decryption.
It is not a secure cipher and must not be used for real files or messages.
"""

import hashlib


BLOCK_SIZE = 8
ROUNDS = 8


def round_function(right_half, key, round_number):
    """Hash the right half with a round-specific key to make a 32-bit value."""
    round_key = hashlib.sha256(key + bytes([round_number])).digest()
    return hashlib.sha256(round_key + right_half).digest()[:4]


def encrypt_block(block, key):
    """Apply Feistel rounds; swapping the halves makes reversal straightforward."""
    left, right = block[:4], block[4:]
    for round_number in range(ROUNDS):
        left, right = right, bytes(a ^ b for a, b in zip(left, round_function(right, key, round_number)))
    return left + right


def decrypt_block(block, key):
    """Undo Feistel rounds in reverse order using the same round function."""
    left, right = block[:4], block[4:]
    for round_number in reversed(range(ROUNDS)):
        left, right = bytes(a ^ b for a, b in zip(right, round_function(left, key, round_number))), left
    return left + right


def pad(data):
    """Pad to a whole block, always adding at least one byte of padding."""
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length


def unpad(data):
    """Remove and validate the padding added before encryption."""
    if not data:
        raise ValueError("Decrypted data is empty.")
    padding_length = data[-1]
    if not 1 <= padding_length <= BLOCK_SIZE or data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid padding; the key or ciphertext may be incorrect.")
    return data[:-padding_length]


def encrypt(data, key):
    """Pad input and encrypt each independent 8-byte block."""
    if not key:
        raise ValueError("The key must not be empty.")
    padded = pad(data)
    return b"".join(encrypt_block(padded[index : index + BLOCK_SIZE], key) for index in range(0, len(padded), BLOCK_SIZE))


def decrypt(ciphertext, key):
    """Decrypt every block and remove its padding."""
    if not key or not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Provide a non-empty key and ciphertext of whole blocks.")
    padded = b"".join(
        decrypt_block(ciphertext[index : index + BLOCK_SIZE], key)
        for index in range(0, len(ciphertext), BLOCK_SIZE)
    )
    return unpad(padded)


def main():
    print("Educational custom cipher (not secure for real use).")
    message = input("Enter a message: ").encode("utf-8")
    key = input("Enter a key: ").encode("utf-8")
    ciphertext = encrypt(message, key)
    recovered = decrypt(ciphertext, key)
    print("Ciphertext (hex):", ciphertext.hex())
    print("Recovered message:", recovered.decode("utf-8"))
    print("This simple construction has no authentication and is not production cryptography.")


if __name__ == "__main__":
    main()
