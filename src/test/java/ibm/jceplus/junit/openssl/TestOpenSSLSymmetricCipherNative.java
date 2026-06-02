/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openssl;

import com.ibm.crypto.plus.provider.base.OCKException;
import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapterNonFIPS;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for OpenSSL symmetric cipher native implementation.
 * Tests OpenSSLSymmetricCipher.c functionality including:
 * - Multiple algorithms (AES-128/192/256, ChaCha20)
 * - Multiple modes (CBC, CTR, ECB, OFB, CFB)
 * - Padding modes (PKCS5, NoPadding)
 * - Streaming operations (update/final)
 * - Cipher reinitialization
 * - Edge cases (zero-length input, large data)
 *
 * Note: DES and 3DES tests removed - not yet implemented in OpenSSL native code
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLSymmetricCipherNative {

    private static NativeOpenSSLAdapterNonFIPS adapter;
    private static final byte[] TEST_PLAINTEXT = "OpenSSL symmetric cipher test data for encryption".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public void setUp() {
        try {
            adapter = NativeOpenSSLAdapterNonFIPS.getInstance();
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL adapter: " + e.getMessage());
        }
    }

    // ========================================
    // AES Tests - Multiple Key Sizes
    // ========================================

    @Test
    public void testAES128_CBC_PKCS5Padding() throws Exception {
        testCipherRoundTrip("AES-128-CBC", 16, 16, true);
    }

    @Test
    public void testAES192_CBC_PKCS5Padding() throws Exception {
        testCipherRoundTrip("AES-192-CBC", 24, 16, true);
    }

    @Test
    public void testAES256_CBC_PKCS5Padding() throws Exception {
        testCipherRoundTrip("AES-256-CBC", 32, 16, true);
    }

    @Test
    public void testAES128_CBC_NoPadding() throws Exception {
        // For NoPadding, plaintext must be multiple of block size
        byte[] plaintext = new byte[32]; // 2 blocks
        Arrays.fill(plaintext, (byte) 0x42);
        testCipherRoundTripWithData("AES-128-CBC", 16, 16, false, plaintext);
    }

    // ========================================
    // AES Tests - Multiple Modes
    // ========================================

    @Test
    public void testAES128_CTR_NoPadding() throws Exception {
        testCipherRoundTrip("AES-128-CTR", 16, 16, false);
    }

    @Test
    public void testAES128_ECB_PKCS5Padding() throws Exception {
        testCipherRoundTrip("AES-128-ECB", 16, 0, true); // ECB has no IV
    }

    @Test
    public void testAES128_OFB_NoPadding() throws Exception {
        testCipherRoundTrip("AES-128-OFB", 16, 16, false);
    }

    @Test
    public void testAES128_CFB_NoPadding() throws Exception {
        testCipherRoundTrip("AES-128-CFB", 16, 16, false);
    }

    // ========================================
    // ChaCha20 Tests
    // ========================================

    @Test
    public void testChaCha20_NoPadding() throws Exception {
        testCipherRoundTrip("ChaCha20", 32, 16, false);
    }

    // ========================================
    // Streaming Operations Tests
    // ========================================

    @Test
    public void testAES_CBC_StreamingEncryptDecrypt() throws Exception {
        byte[] key = sequentialBytes(16, 0x10);
        byte[] iv = sequentialBytes(16, 0x20);
        byte[] plaintext = "Streaming test data for AES-CBC with multiple update calls".getBytes(StandardCharsets.UTF_8);

        // Encrypt with streaming
        long encryptCtx = adapter.CIPHER_create("AES-128-CBC");
        try {
            adapter.CIPHER_init(encryptCtx, 1, 1, key, iv); // encrypt=1, padding=1 (PKCS5)

            byte[] ciphertext = new byte[plaintext.length + 32]; // Extra space for padding
            int offset = 0;

            // Update in chunks
            int chunk1Len = 20;
            int len1 = adapter.CIPHER_encryptUpdate(encryptCtx, plaintext, 0, chunk1Len,
                    ciphertext, offset, false);
            offset += len1;

            int chunk2Len = plaintext.length - chunk1Len;
            int len2 = adapter.CIPHER_encryptUpdate(encryptCtx, plaintext, chunk1Len, chunk2Len,
                    ciphertext, offset, false);
            offset += len2;

            // Final
            int len3 = adapter.CIPHER_encryptFinal(encryptCtx, null, 0, 0, ciphertext, offset, false);
            offset += len3;

            int totalCipherLen = offset;
            assertTrue(totalCipherLen > 0, "Ciphertext length should be positive");

            // Decrypt with streaming
            long decryptCtx = adapter.CIPHER_create("AES-128-CBC");
            try {
                adapter.CIPHER_init(decryptCtx, 0, 1, key, iv); // decrypt=0, padding=1

                byte[] decrypted = new byte[totalCipherLen];
                int decOffset = 0;

                // Update in chunks
                int decChunk1 = 16; // One block
                int decLen1 = adapter.CIPHER_decryptUpdate(decryptCtx, ciphertext, 0, decChunk1,
                        decrypted, decOffset, false);
                decOffset += decLen1;

                int decChunk2 = totalCipherLen - decChunk1;
                int decLen2 = adapter.CIPHER_decryptUpdate(decryptCtx, ciphertext, decChunk1, decChunk2,
                        decrypted, decOffset, false);
                decOffset += decLen2;

                // Final
                int decLen3 = adapter.CIPHER_decryptFinal(decryptCtx, null, 0, 0, decrypted, decOffset, false);
                decOffset += decLen3;

                int totalPlainLen = decOffset;
                assertEquals(plaintext.length, totalPlainLen, "Decrypted length should match original");

                byte[] actualPlaintext = Arrays.copyOf(decrypted, totalPlainLen);
                assertArrayEquals(plaintext, actualPlaintext, "Streaming round-trip should match");
            } finally {
                adapter.CIPHER_delete(decryptCtx);
            }
        } finally {
            adapter.CIPHER_delete(encryptCtx);
        }
    }

    // ========================================
    // Cipher Reinitialization Tests
    // ========================================

    @Test
    public void testCipherReinitialization() throws Exception {
        byte[] key = sequentialBytes(16, 0x30);
        byte[] iv1 = sequentialBytes(16, 0x40);
        byte[] iv2 = sequentialBytes(16, 0x50);
        byte[] plaintext = "Test reinitialization".getBytes(StandardCharsets.UTF_8);

        long cipherId = adapter.CIPHER_create("AES-128-CBC");
        try {
            // First encryption
            adapter.CIPHER_init(cipherId, 1, 1, key, iv1);
            byte[] ciphertext1 = new byte[plaintext.length + 32];
            int len1 = adapter.CIPHER_encryptUpdate(cipherId, plaintext, 0, plaintext.length,
                    ciphertext1, 0, false);
            len1 += adapter.CIPHER_encryptFinal(cipherId, null, 0, 0, ciphertext1, len1, false);

            // Reinitialize with different IV
            adapter.CIPHER_init(cipherId, 1, 1, key, iv2);
            byte[] ciphertext2 = new byte[plaintext.length + 32];
            int len2 = adapter.CIPHER_encryptUpdate(cipherId, plaintext, 0, plaintext.length,
                    ciphertext2, 0, false);
            len2 += adapter.CIPHER_encryptFinal(cipherId, null, 0, 0, ciphertext2, len2, false);

            // Ciphertexts should be different (different IVs)
            assertFalse(Arrays.equals(Arrays.copyOf(ciphertext1, len1), Arrays.copyOf(ciphertext2, len2)),
                    "Ciphertexts with different IVs should differ");
        } finally {
            adapter.CIPHER_delete(cipherId);
        }
    }

    // ========================================
    // Edge Case Tests
    // ========================================

    @Test
    public void testZeroLengthInput_NoPadding() throws Exception {
        byte[] key = sequentialBytes(16, 0x60);
        byte[] iv = sequentialBytes(16, 0x70);
        byte[] emptyInput = new byte[0];

        long cipherId = adapter.CIPHER_create("AES-128-CTR");
        try {
            adapter.CIPHER_init(cipherId, 1, 0, key, iv); // NoPadding

            byte[] output = new byte[16];
            int len = adapter.CIPHER_encryptUpdate(cipherId, emptyInput, 0, 0, output, 0, false);
            len += adapter.CIPHER_encryptFinal(cipherId, null, 0, 0, output, len, false);

            assertEquals(0, len, "Zero-length input should produce zero-length output");
        } finally {
            adapter.CIPHER_delete(cipherId);
        }
    }

    @Test
    public void testLargeData() throws Exception {
        byte[] key = sequentialBytes(32, 0x80);
        byte[] iv = sequentialBytes(16, 0x90);
        byte[] largePlaintext = new byte[10000]; // 10KB
        Arrays.fill(largePlaintext, (byte) 0xAB);

        testCipherRoundTripWithData("AES-256-CBC", 32, 16, true, largePlaintext);
    }

    @Test
    public void testSingleBlockExactly() throws Exception {
        byte[] key = sequentialBytes(16, 0xA0);
        byte[] iv = sequentialBytes(16, 0xB0);
        byte[] singleBlock = new byte[16]; // Exactly one AES block
        Arrays.fill(singleBlock, (byte) 0xCD);

        testCipherRoundTripWithData("AES-128-CBC", 16, 16, false, singleBlock);
    }

    // ========================================
    // Cipher Properties Tests
    // ========================================

    @Test
    public void testCipherProperties() throws Exception {
        long aes128 = adapter.CIPHER_create("AES-128-CBC");
        try {
            // Query properties before initialization (they come from cipher type)
            assertEquals(16, adapter.CIPHER_getBlockSize(aes128), "AES block size should be 16");
            assertEquals(16, adapter.CIPHER_getKeyLength(aes128), "AES-128 key length should be 16");
            assertEquals(16, adapter.CIPHER_getIVLength(aes128), "AES-CBC IV length should be 16");
            
            // Now initialize and use the cipher
            byte[] key = sequentialBytes(16, 0x10);
            byte[] iv = sequentialBytes(16, 0x20);
            adapter.CIPHER_init(aes128, 1, 1, key, iv);
        } finally {
            adapter.CIPHER_delete(aes128);
        }

        long aes256 = adapter.CIPHER_create("AES-256-CTR");
        try {
            // CTR mode is a stream cipher mode, so block size is 1
            assertEquals(1, adapter.CIPHER_getBlockSize(aes256), "AES-CTR block size should be 1 (stream mode)");
            assertEquals(32, adapter.CIPHER_getKeyLength(aes256), "AES-256 key length should be 32");
            assertEquals(16, adapter.CIPHER_getIVLength(aes256), "AES-CTR IV length should be 16");
            
            byte[] key = sequentialBytes(32, 0x30);
            byte[] iv = sequentialBytes(16, 0x40);
            adapter.CIPHER_init(aes256, 1, 0, key, iv);
        } finally {
            adapter.CIPHER_delete(aes256);
        }

    }

    // ========================================
    // Helper Methods
    // ========================================

    private void testCipherRoundTrip(String algorithm, int keyLen, int ivLen, boolean usePadding) throws Exception {
        testCipherRoundTripWithData(algorithm, keyLen, ivLen, usePadding, TEST_PLAINTEXT);
    }

    private void testCipherRoundTripWithData(String algorithm, int keyLen, int ivLen, boolean usePadding, byte[] plaintext) throws Exception {
        byte[] key = sequentialBytes(keyLen, 0x11);
        byte[] iv = ivLen > 0 ? sequentialBytes(ivLen, 0x22) : null;

        // Encrypt
        long encryptCtx = adapter.CIPHER_create(algorithm);
        byte[] ciphertext = null;
        int cipherLen = 0;
        try {
            int paddingMode = usePadding ? 1 : 0; // 1=PKCS5, 0=NoPadding
            adapter.CIPHER_init(encryptCtx, 1, paddingMode, key, iv); // encrypt=1

            byte[] tempCipher = new byte[plaintext.length + 32]; // Extra space for padding
            int len1 = adapter.CIPHER_encryptUpdate(encryptCtx, plaintext, 0, plaintext.length,
                    tempCipher, 0, false);
            int len2 = adapter.CIPHER_encryptFinal(encryptCtx, null, 0, 0, tempCipher, len1, false);
            cipherLen = len1 + len2;
            ciphertext = Arrays.copyOf(tempCipher, cipherLen);

            assertTrue(cipherLen > 0, "Ciphertext length should be positive");
        } finally {
            adapter.CIPHER_delete(encryptCtx);
        }

        // Decrypt
        long decryptCtx = adapter.CIPHER_create(algorithm);
        try {
            int paddingMode = usePadding ? 1 : 0;
            adapter.CIPHER_init(decryptCtx, 0, paddingMode, key, iv); // decrypt=0

            byte[] tempPlain = new byte[cipherLen];
            int len1 = adapter.CIPHER_decryptUpdate(decryptCtx, ciphertext, 0, cipherLen,
                    tempPlain, 0, false);
            int len2 = adapter.CIPHER_decryptFinal(decryptCtx, null, 0, 0, tempPlain, len1, false);
            int plainLen = len1 + len2;

            byte[] decrypted = Arrays.copyOf(tempPlain, plainLen);
            assertArrayEquals(plaintext, decrypted,
                    String.format("Round-trip failed for %s (keyLen=%d, ivLen=%d, padding=%b)",
                            algorithm, keyLen, ivLen, usePadding));
        } finally {
            adapter.CIPHER_delete(decryptCtx);
        }
    }

    private byte[] sequentialBytes(int length, int start) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) ((start + i) & 0xFF);
        }
        return result;
    }
}


