
# Diffie-Hellman Key Exchange with MITM Attack

# Public parameters
p = 23
g = 5

# Private keys
alice_private = 6
bob_private = 15

# Eve's private keys
eve_private_alice = 7
eve_private_bob = 11

print("DIFFIE-HELLMAN KEY EXCHANGE")
print("--------------------------------")

# Generate public keys
alice_public = pow(g, alice_private, p)
bob_public = pow(g, bob_private, p)

print("\nAlice Public Key:", alice_public)
print("Bob Public Key:", bob_public)

# Normal shared secret
alice_shared = pow(bob_public, alice_private, p)
bob_shared = pow(alice_public, bob_private, p)

print("\nNORMAL KEY EXCHANGE")
print("Alice Shared Secret:", alice_shared)
print("Bob Shared Secret:", bob_shared)

if alice_shared == bob_shared:
    print("Shared key established successfully!")

# -----------------------------------
# MAN IN THE MIDDLE ATTACK
# -----------------------------------

print("\n\nMAN-IN-THE-MIDDLE ATTACK")
print("--------------------------------")

# Eve generates two public keys
eve_public_alice = pow(g, eve_private_alice, p)
eve_public_bob = pow(g, eve_private_bob, p)

print("Eve Public Key for Alice:", eve_public_bob)
print("Eve Public Key for Bob:", eve_public_alice)

# Alice unknowingly shares key with Eve
alice_eve_key = pow(
    eve_public_bob, alice_private, p
)

# Bob unknowingly shares key with Eve
bob_eve_key = pow(
    eve_public_alice, bob_private, p
)

# Eve calculates the same two keys
eve_alice_key = pow(
    alice_public, eve_private_bob, p
)

eve_bob_key = pow(
    bob_public, eve_private_alice, p
)

print("\nAlice Shared Key:", alice_eve_key)
print("Eve-Alice Shared Key:", eve_alice_key)

print("\nBob Shared Key:", bob_eve_key)
print("Eve-Bob Shared Key:", eve_bob_key)

if (alice_eve_key == eve_alice_key and
        bob_eve_key == eve_bob_key):
    print("\nMITM ATTACK SUCCESSFUL!")
    print("Eve has established separate keys with Alice and Bob.")
    print("Eve can intercept their communication.")
