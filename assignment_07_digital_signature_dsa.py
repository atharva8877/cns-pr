
# Digital Signature Standard (DSS) Implementation
# Algorithm: DSA with SHA-256

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Step 1: Generate DSA Key Pair
print("DIGITAL SIGNATURE STANDARD")
print("--------------------------------")

key = DSA.generate(2048)

private_key = key
public_key = key.publickey()

print("\nDSA Key Pair Generated Successfully!")

# Step 2: Accept Message
message = input("\nEnter message to sign: ")

message_bytes = message.encode('utf-8')

# Step 3: Generate Digital Signature
hash_object = SHA256.new(message_bytes)

signer = DSS.new(private_key, 'fips-186-3')

signature = signer.sign(hash_object)

print("\nOriginal Message:", message)
print("SHA-256 Digest:", hash_object.hexdigest())
print("Digital Signature:", signature.hex())

# Step 4: Verify Original Message
print("\nSIGNATURE VERIFICATION")
print("--------------------------------")

verifier = DSS.new(public_key, 'fips-186-3')

try:
    verifier.verify(
        SHA256.new(message_bytes),
        signature
    )
    print("Signature Verified Successfully!")
    print("Message is authentic and unchanged.")

except ValueError:
    print("Signature Verification Failed!")

# Step 5: Modify Message and Verify Again
modified_message = message + " Modified"

print("\nTAMPER DETECTION")
print("--------------------------------")
print("Modified Message:", modified_message)

try:
    verifier.verify(
        SHA256.new(modified_message.encode('utf-8')),
        signature
    )
    print("Signature Valid!")

except ValueError:
    print("Signature Verification Failed!")
    print("Message has been modified!")
