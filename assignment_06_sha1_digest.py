"""Assignment 6: calculate SHA-1 digests and observe the avalanche effect."""

import hashlib


def sha1_digest(text):
    """Hash UTF-8 bytes and return the standard 40-character hexadecimal digest."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def main():
    text = input("Enter text: ")
    changed_text = text + " "
    print("Original text:", repr(text))
    print("SHA-1 digest: ", sha1_digest(text))
    print("\nChanged text: ", repr(changed_text))
    print("SHA-1 digest: ", sha1_digest(changed_text))


if __name__ == "__main__":
    main()
