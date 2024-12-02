import time
import psutil
import hashlib
import os

# Function to compute SHA-256 hash and split into two 128-bit halves
def compute_sha256_hash(data):
    hash_object = hashlib.sha256(data.encode('utf-8'))
    hash_bytes = hash_object.digest()
    return hash_bytes[:16], hash_bytes[16:]  # First and second 128-bit halves

# Function to XOR 32-bit hash segments with the original key
def xor_with_key(hash_segments, original_keys):
    return [
        int.from_bytes(hash_segments[i], 'big') ^ int.from_bytes(original_keys[i], 'big') 
        for i in range(4)
    ]

# Enhanced TEA encryption
def enhanced_tea_encrypt(plaintext_block, key, round_keys_store):
    L0 = int.from_bytes(plaintext_block[:4], 'big')
    R0 = int.from_bytes(plaintext_block[4:], 'big')

    k0 = key[:4]
    k1 = key[4:8]
    k2 = key[8:12]
    k3 = key[12:]

    delta = 0x9e3779b9 # derived from golden ratio constant
    sum = 0 # to calculate the sum of delta throughout the rounds

    hash1, hash2 = compute_sha256_hash(plaintext_block.decode(errors='ignore'))
    first_half_segments = [hash1[i:i+4] for i in range(0, 16, 4)] # list of hash segments
    second_half_segments = [hash2[i:i+4] for i in range(0, 16, 4)]

    for i in range(32):
        if i % 2 == 0:
            # Use first 128-bit hash for even rounds
            key_segments = xor_with_key(first_half_segments, [k0, k1, k2, k3])
        else:
            # Use second 128-bit hash for odd rounds
            key_segments = xor_with_key(second_half_segments, [k0, k1, k2, k3])

        round_keys_store.append(key_segments)  # Store round keys for decryption

        sum = (sum + delta) & 0xffffffff
        L0 = (L0 + (((R0 << 4) + key_segments[0]) ^ (R0 + sum) ^ ((R0 >> 5) + key_segments[1]))) & 0xffffffff
        R0 = (R0 + (((L0 << 4) + key_segments[2]) ^ (L0 + sum) ^ ((L0 >> 5) + key_segments[3]))) & 0xffffffff

    ciphertext_block = L0.to_bytes(4, 'big') + R0.to_bytes(4, 'big')
    return ciphertext_block

# Enhanced TEA decryption
def enhanced_tea_decrypt(ciphertext_block, key, round_keys_store):
    v0 = int.from_bytes(ciphertext_block[:4], 'big')
    v1 = int.from_bytes(ciphertext_block[4:], 'big')

    delta = 0x9e3779b9
    sum = (delta * 32) & 0xffffffff  # Initial sum for decryption

    for i in range(31, -1, -1):  # Loop in reverse for decryption
        key_segments = round_keys_store[i]

        v1 = (v1 - (((v0 << 4) + key_segments[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key_segments[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + key_segments[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key_segments[1]))) & 0xffffffff
        sum = (sum - delta) & 0xffffffff

    plaintext_block = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
    return plaintext_block

# Function to handle encryption of large plaintexts
def encrypt_large_plaintext(plaintext, key):
    blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    ciphertext = b""
    round_keys_store = []  # Store round keys for all blocks

    for block in blocks:
        if len(block) < 8:
            block = block.ljust(8, b'\x00')  # Pad block if necessary
        ciphertext += enhanced_tea_encrypt(block, key, round_keys_store)

    return ciphertext, round_keys_store

# Function to handle decryption of large ciphertexts
def decrypt_large_ciphertext(ciphertext, key, round_keys_store):
    blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
    plaintext = b""
    rounds_per_block = 32  # Now 32 rounds instead of 16

    for id, block in enumerate(blocks):
        # Adjust slicing to retrieve the correct 32 keys for this block
        plaintext += enhanced_tea_decrypt(
            block, 
            key, 
            round_keys_store[id * rounds_per_block : (id + 1) * rounds_per_block]
        )

    return plaintext

# Function to measure performance of encryption
def measure_encryption_performance(plaintext_size):
    plaintext = b"Hello, this is a test message for TEA encryption!" * plaintext_size
    key = b"0123456789abcdef"  # 16-byte key for TEA

    start_cpu = psutil.cpu_percent(interval=None)
    start_time = time.perf_counter()

    # Encrypt plaintext
    ciphertext, round_keys_store = encrypt_large_plaintext(plaintext, key)

    end_time = time.perf_counter()
    end_cpu = psutil.cpu_percent(interval=0.1)

    encryption_time = end_time - start_time
    cpu_utilization = end_cpu - start_cpu

    # Memory usage
    process = psutil.Process(os.getpid())
    memory_used = process.memory_info().rss / 1024 / 1024  # Convert to MB

    print(f"Plaintext size: {plaintext_size * 8} bits, Encryption time: {encryption_time:.6f} seconds")
    print(f"CPU Utilization: {cpu_utilization:.2f}%, Memory Used: {memory_used:.4f} MB\n")

    # Decrypt the ciphertext
    decrypted_plaintext = decrypt_large_ciphertext(ciphertext, key, round_keys_store)

    # Verification of decryption
    if plaintext == decrypted_plaintext:
        print("Decryption successful! Original plaintext matches decrypted plaintext.")
    else:
        print("Decryption failed! Original plaintext does not match decrypted plaintext.")

    # Display results
    print("Ciphertext (encrypted):", ciphertext.hex())
    print("Decrypted plaintext (hex):", decrypted_plaintext.hex())
    print("Decrypted plaintext (text):", decrypted_plaintext.decode(errors='ignore'))

    return encryption_time, cpu_utilization, memory_used

# Test with different plaintext sizes
plaintext_sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048]

# Running the tests for each plaintext size
for size in plaintext_sizes:
    measure_encryption_performance(size)