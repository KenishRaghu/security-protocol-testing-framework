/*
 * Cryptographic Algorithm Test Suite
 * Tests AES, RSA, and SHA implementations
 * 
 * INTERVIEW: "Walk me through how you tested AES encryption"
 * - Encrypt known plaintext with known key
 * - Compare ciphertext with expected output
 * - Decrypt and verify we get original plaintext back
 */

#include <iostream>
#include <cstring>
#include <stdexcept>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "test_framework.h"

namespace SecurityTest {
namespace CryptoTests {

/*
 * ============================================
 * AES ENCRYPTION TESTS (Symmetric Encryption)
 * ============================================
 * 
 * INTERVIEW TIP: AES is a block cipher
 * - Block size: 128 bits (16 bytes)
 * - Key sizes: 128, 192, or 256 bits
 * - We test AES-256-CBC (most common in enterprise)
 */

// Test 1: Basic AES-256 Encryption/Decryption
bool testAES256BasicEncryptDecrypt() {
    // 256-bit key (32 bytes)
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    // Initialization Vector (IV) - 16 bytes for CBC mode
    // INTERVIEW: Why IV? Ensures same plaintext encrypts differently each time
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);  // Need copy because encryption modifies IV
    
    // Test data (must be multiple of 16 bytes for basic test)
    const char* plaintext = "This is a test!!";  // Exactly 16 bytes
    size_t plaintext_len = strlen(plaintext);
    
    unsigned char ciphertext[32];  // Buffer for encrypted data
    unsigned char decrypted[32];   // Buffer for decrypted data
    int outlen, tmplen;
    
    // --- ENCRYPTION ---
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    // Initialize encryption operation
    // INTERVIEW: EVP is OpenSSL's high-level API (recommended over low-level)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Disable padding for this basic test
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Perform encryption
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, 
                          (unsigned char*)plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outlen += tmplen;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // --- DECRYPTION ---
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    // Initialize decryption (note: using iv_copy since iv was modified)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv_copy) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Perform decryption
    int decrypted_len;
    if (EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, 
                          ciphertext, outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    decrypted_len += tmplen;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // VERIFY: Decrypted text matches original
    // INTERVIEW: This is the critical assertion - proves round-trip works
    return (memcmp(plaintext, decrypted, plaintext_len) == 0);
}

// Test 2: AES with Wrong Key Should Fail
// INTERVIEW: "How do you test negative cases?"
bool testAESWrongKeyFails() {
    unsigned char correct_key[32], wrong_key[32];
    unsigned char iv[16], iv_copy[16];
    
    // Generate random keys
    RAND_bytes(correct_key, 32);
    RAND_bytes(wrong_key, 32);
    RAND_bytes(iv, 16);
    memcpy(iv_copy, iv, 16);
    
    const char* plaintext = "Secret message!!";
    unsigned char ciphertext[32];
    unsigned char decrypted[32];
    int outlen, tmplen;
    
    // Encrypt with correct key
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, correct_key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char*)plaintext, 16);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    
    // Try to decrypt with WRONG key
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, wrong_key, iv_copy);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, decrypted, &outlen, ciphertext, 16);
    EVP_DecryptFinal_ex(ctx, decrypted + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    
    // Decrypted data should NOT match original (test passes if they differ)
    return (memcmp(plaintext, decrypted, 16) != 0);
}

/*
 * ============================================
 * SHA-256 HASH TESTS
 * ============================================
 * 
 * INTERVIEW TIP: Hashing properties
 * - Deterministic: Same input = same output
 * - One-way: Can't reverse hash to get input
 * - Collision resistant: Hard to find two inputs with same hash
 */

// Test 3: SHA-256 Known Answer Test (KAT)
// INTERVIEW: "What's a Known Answer Test?"
// Answer: Test against pre-computed correct values
bool testSHA256KnownAnswer() {
    const char* input = "hello";
    
    // Pre-computed SHA-256 hash of "hello"
    // You can verify: echo -n "hello" | sha256sum
    unsigned char expected_hash[32] = {
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
    };
    
    unsigned char computed_hash[32];
    
    // Compute SHA-256
    SHA256((unsigned char*)input, strlen(input), computed_hash);
    
    // Compare with expected
    return CryptoUtils::secureCompare(expected_hash, computed_hash, 32);
}

// Test 4: SHA-256 Determinism Test
// Same input must always produce same hash
bool testSHA256Determinism() {
    const char* input = "Test determinism property";
    unsigned char hash1[32], hash2[32];
    
    SHA256((unsigned char*)input, strlen(input), hash1);
    SHA256((unsigned char*)input, strlen(input), hash2);
    
    return CryptoUtils::secureCompare(hash1, hash2, 32);
}

// Test 5: SHA-256 Avalanche Effect
// INTERVIEW: "What's the avalanche effect?"
// Answer: Small change in input = large change in output
bool testSHA256AvalancheEffect() {
    const char* input1 = "test1";
    const char* input2 = "test2";  // Only 1 character different
    
    unsigned char hash1[32], hash2[32];
    SHA256((unsigned char*)input1, strlen(input1), hash1);
    SHA256((unsigned char*)input2, strlen(input2), hash2);
    
    // Count differing bits
    int differing_bits = 0;
    for (int i = 0; i < 32; i++) {
        unsigned char xor_result = hash1[i] ^ hash2[i];
        while (xor_result) {
            differing_bits += xor_result & 1;
            xor_result >>= 1;
        }
    }
    
    // Good hash should have ~50% bits different (128 of 256)
    // We accept anything over 25% (64 bits) as passing
    return differing_bits > 64;
}

/*
 * ============================================
 * RSA TESTS (Asymmetric Encryption)
 * ============================================
 * 
 * INTERVIEW TIP: RSA uses key pairs
 * - Public key: Anyone can have, used to encrypt
 * - Private key: Keep secret, used to decrypt
 * - Also used for digital signatures
 */

// Test 6: RSA Key Generation
bool testRSAKeyGeneration() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY* pkey = NULL;
    
    if (!ctx) return false;
    
    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // Set key size to 2048 bits (minimum recommended)
    // INTERVIEW: Why 2048? NIST recommendation for security until 2030
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // Generate the key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // Verify key was generated
    bool success = (pkey != NULL);
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return success;
}

// Register all crypto tests
void registerCryptoTests(TestSuite& suite) {
    suite.addTest(TestCase(
        "AES-256 Basic Encrypt/Decrypt",
        "Verify AES-256-CBC encryption and decryption round-trip",
        testAES256BasicEncryptDecrypt
    ));
    
    suite.addTest(TestCase(
        "AES Wrong Key Fails",
        "Verify decryption with wrong key produces garbage",
        testAESWrongKeyFails
    ));
    
    suite.addTest(TestCase(
        "SHA-256 Known Answer Test",
        "Verify SHA-256 produces correct hash for known input",
        testSHA256KnownAnswer
    ));
    
    suite.addTest(TestCase(
        "SHA-256 Determinism",
        "Verify same input always produces same hash",
        testSHA256Determinism
    ));
    
    suite.addTest(TestCase(
        "SHA-256 Avalanche Effect",
        "Verify small input changes cause large output changes",
        testSHA256AvalancheEffect
    ));
    
    suite.addTest(TestCase(
        "RSA Key Generation",
        "Verify RSA-2048 key pair can be generated",
        testRSAKeyGeneration
    ));
}

} // namespace CryptoTests
} // namespace SecurityTest