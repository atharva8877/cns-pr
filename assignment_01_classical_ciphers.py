"""Assignment 1: five classical ciphers. These are for learning, not security."""


def clean(text):
    """Keep A-Z so the examples use one consistent alphabet."""
    return "".join(c for c in text.upper() if c.isalpha() and c.isascii())


def caesar(text, shift):
    """Shift each letter; use a negative shift to decrypt."""
    return "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in clean(text))


def vigenere(text, key, decrypt=False):
    """Add or subtract repeated key-letter shifts."""
    text, key = clean(text), clean(key)
    if not key:
        raise ValueError("Key must contain letters.")
    sign = -1 if decrypt else 1
    return "".join(chr((ord(c) - 65 + sign * (ord(key[i % len(key)]) - 65)) % 26 + 65)
                   for i, c in enumerate(text))


def playfair(text, key, decrypt=False):
    """Encrypt/decrypt letter pairs using the Playfair square rules."""
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # I and J share one square.
    square = list(dict.fromkeys(clean(key).replace("J", "I") + alphabet))
    pos = {c: divmod(i, 5) for i, c in enumerate(square)}
    text = clean(text).replace("J", "I")
    if decrypt:
        if len(text) % 2:
            raise ValueError("Ciphertext needs an even number of letters.")
        pairs = zip(text[::2], text[1::2])
    else:
        # Insert X between repeated letters and pad a final single letter.
        pairs, i = [], 0
        while i < len(text):
            a = text[i]
            b = text[i + 1] if i + 1 < len(text) else "X"
            pairs.append((a, b if b != a else "X"))
            i += 2 if b != a else 1
    step, out = (-1 if decrypt else 1), []
    for a, b in pairs:
        r1, c1 = pos[a]
        r2, c2 = pos[b]
        if r1 == r2:  # Same row: move left/right.
            out += [square[r1 * 5 + (c1 + step) % 5], square[r2 * 5 + (c2 + step) % 5]]
        elif c1 == c2:  # Same column: move up/down.
            out += [square[((r1 + step) % 5) * 5 + c1], square[((r2 + step) % 5) * 5 + c2]]
        else:  # Rectangle: exchange columns.
            out += [square[r1 * 5 + c2], square[r2 * 5 + c1]]
    return "".join(out)


def rail_fence(text, rails, decrypt=False):
    """Write diagonally across rails; read diagonally to undo the transposition."""
    text = clean(text)
    if rails < 2:
        raise ValueError("Use at least two rails.")
    path, row, step = [], 0, 1
    for _ in text:
        path.append(row)
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    if not decrypt:
        return "".join(c for rail in range(rails) for c, r in zip(text, path) if r == rail)
    counts = [path.count(r) for r in range(rails)]
    chunks, i = [], 0
    for n in counts:
        chunks.append(iter(text[i:i + n]))
        i += n
    return "".join(next(chunks[r]) for r in path)


def columnar(text, key, decrypt=False):
    """Transpose a row-filled grid; key letters determine column read order."""
    text, key = clean(text), clean(key)
    if not key:
        raise ValueError("Key must contain letters.")
    width = len(key)
    order = sorted(range(width), key=lambda c: (key[c], c))
    if not decrypt:
        return "".join(text[c::width] for c in order)
    rows, extra = divmod(len(text), width)
    heights = [rows + (c < extra) for c in range(width)]
    grid, i = [""] * width, 0
    for c in order:
        grid[c], i = text[i:i + heights[c]], i + heights[c]
    return "".join(grid[c][r] for r in range(rows + bool(extra))
                   for c in range(width) if r < len(grid[c]))


def main():
    print("1 Caesar | 2 Playfair | 3 Vigenere | 4 Rail Fence | 5 Row/Column")
    choice, text = input("Choose: "), input("Text: ")
    if choice == "1":
        shift = int(input("Shift: "))
        encrypted = caesar(text, shift)
        decrypted = caesar(encrypted, -shift)
    elif choice in ("2", "3", "5"):
        while True:
            key = input("Key: ")
            if clean(key):
                break
            print("Key must contain letters. Please enter a valid key.")
        if choice == "2":
            encrypted = playfair(text, key)
            decrypted = playfair(encrypted, key, True)
        elif choice == "3":
            encrypted = vigenere(text, key)
            decrypted = vigenere(encrypted, key, True)
        else:
            encrypted = columnar(text, key)
            decrypted = columnar(encrypted, key, True)
    elif choice == "4":
        rails = int(input("Rails: "))
        encrypted = rail_fence(text, rails)
        decrypted = rail_fence(encrypted, rails, True)
    else:
        raise ValueError("Choose 1 to 5.")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()
