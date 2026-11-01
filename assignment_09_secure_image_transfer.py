
import os
import time
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------------------------------------
# SECURE IMAGE TRANSMISSION SYSTEM
# AES-256-GCM
# ---------------------------------------

KEY_FILE = "secret.key"

# Generate or load shared secret key
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = get_random_bytes(32)

        with open(KEY_FILE, "wb") as f:
            f.write(key)

        print("Secret Key Generated Successfully!")

    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()

    if len(key) != 32:
        raise ValueError("Invalid AES-256 key!")

    return key


# ---------------------------------------
# IMAGE ENCRYPTION (ALICE)
# ---------------------------------------

def encrypt_image(image_path, key):

    with open(image_path, "rb") as f:
        image_data = f.read()

    # Generate unique 96-bit nonce
    nonce = get_random_bytes(12)

    # Create timestamp
    timestamp = int(time.time())

    # Pack timestamp into 8 bytes
    header = struct.pack(">Q", timestamp)

    # Initialize AES-GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Authenticate timestamp
    cipher.update(header)

    # Encrypt image
    ciphertext, tag = cipher.encrypt_and_digest(image_data)

    # Save encrypted image package
    with open("encrypted_image.bin", "wb") as f:
        f.write(header + nonce + tag + ciphertext)

    print("\nIMAGE ENCRYPTION")
    print("-----------------------------")
    print("Original Image:", image_path)
    print("Image encrypted successfully!")
    print("Encrypted File: encrypted_image.bin")
    print("Authentication Tag:", tag.hex())


# ---------------------------------------
# IMAGE DECRYPTION (BOB)
# ---------------------------------------

def decrypt_image(encrypted_path, key):

    with open(encrypted_path, "rb") as f:
        data = f.read()

    # Extract components
    header = data[:8]
    nonce = data[8:20]
    tag = data[20:36]
    ciphertext = data[36:]

    # Check message age (maximum 10 minutes)
    timestamp = struct.unpack(">Q", header)[0]

    if abs(time.time() - timestamp) > 600:
        print("Message expired or timestamp invalid!")
        return

    # Initialize AES-GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Authenticate timestamp
    cipher.update(header)

    try:
        # Verify tag and decrypt
        image_data = cipher.decrypt_and_verify(
            ciphertext, tag
        )

        with open("received_image.png", "wb") as f:
            f.write(image_data)

        print("\nIMAGE DECRYPTION")
        print("-----------------------------")
        print("Authentication Successful!")
        print("Image integrity verified!")
        print("Original Image recovered!")
        print("Saved as: received_image.png")

    except ValueError:
        print("\nSECURITY ALERT!")
        print("Authentication Failed!")
        print("Image may have been modified.")
        print("Decryption rejected!")


# ---------------------------------------
# MAIN PROGRAM
# ---------------------------------------

print("SECURE IMAGE TRANSMISSION SYSTEM")
print("================================")

key = generate_key()

print("\n1. Encrypt Image (Alice)")
print("2. Decrypt Image (Bob)")

choice = input("\nEnter your choice: ")

if choice == "1":

    image_path = input("Enter image path: ")

    if os.path.isfile(image_path):
        encrypt_image(image_path, key)
    else:
        print("Image file not found!")

elif choice == "2":

    encrypted_path = input("Enter encrypted file path: ")

    if os.path.isfile(encrypted_path):
        decrypt_image(encrypted_path, key)
    else:
        print("Encrypted file not found!")

else:
    print("Invalid choice!")
