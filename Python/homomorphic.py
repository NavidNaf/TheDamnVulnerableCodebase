import secrets

# Exploitation notes (timing side-channel):
# 1) Obtain the ability to submit ciphertexts for decryption and measure response time.
# 2) Send many chosen ciphertexts and split them into "fast" vs "slow" decryptions.
# 3) Because decrypt_vulnerable() conditionally does extra work when x > p/2, timing leaks
#    information correlated with the decrypted bit.
# 4) Average enough samples per target ciphertext to reduce noise, then infer the bit from timing.
# 5) Repeat bit-by-bit to recover sensitive plaintext information.

# keygeneration: generate a random odd integer p (the secret key)
def keygen(bitlen=64):
    # secret odd p
    p = secrets.randbits(bitlen) | 1
    return p

# encryption: encrypt a bit m (0 or 1) using the secret key p
def encrypt_bit(m, p):
    # c = m + 2r + p*q  # r, q random (masking)
    r = secrets.randbits(32)
    q = secrets.randbits(64)
    return m + 2*r + p*q

# decryption: decrypt a ciphertext c using the secret key p
def hom_xor(c1, c2):
    # Addition corresponds to XOR mod 2 after decryption in this example scheme
    return c1 + c2

# vulnerable decryption: timing depends on message bit
def decrypt_vulnerable(c, p):
    x = c % p  # intermediate
    # BAD: branch on x (which is correlated with message bit in this example)
    if x > (p >> 1):
        # extra work only on this path (amplifies timing difference)
        for _ in range(2000):
            x = (x * 3 + 1) % p
        x = p - x
    return x & 1

# fixed-time decryption: do the same work regardless of message bit
def decrypt_masked(c, p):
    x = c % p
    cond = 1 if x > (p >> 1) else 0  # 0 or 1

    # do the same work regardless (always run loop)
    y = x
    for _ in range(2000):
        y = (y * 3 + 1) % p
    y = p - y

    # select without if:  x = cond*y + (1-cond)*x
    x = cond * y + (1 - cond) * x
    return x & 1

if __name__ == "__main__":
    p = keygen()
    c0 = encrypt_bit(0, p)
    c1 = encrypt_bit(1, p)

    print("decrypt_vulnerable(c0):", decrypt_vulnerable(c0, p))
    print("decrypt_vulnerable(c1):", decrypt_vulnerable(c1, p))
    print("decrypt_masked(c0):", decrypt_masked(c0, p))
    print("decrypt_masked(c1):", decrypt_masked(c1, p))

    c = hom_xor(c1, c0)
    print("homomorphic XOR (1 xor 0):", decrypt_masked(c, p))
