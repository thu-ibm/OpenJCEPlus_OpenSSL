/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openssl;

import com.ibm.crypto.plus.provider.base.OCKException;
import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapterFIPS;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Assumptions;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * FIPS mode tests for OpenSSL symmetric cipher native implementation.
 * Verifies:
 * - FIPS-approved algorithms work in FIPS mode
 * - Non-FIPS algorithms are rejected in FIPS mode
 * - FIPS context isolation
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLSymmetricCipherFIPS {

    private static NativeOpenSSLAdapterFIPS fipsAdapter;
    private static boolean fipsAvailable = false;
    private static final byte[] TEST_PLAINTEXT = "FIPS mode symmetric cipher test".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public void setUp() {
        try {
            fipsAdapter = NativeOpenSSLAdapterFIPS.getInstance();
            fipsAvailable = true;
        } catch (Exception e) {
            System.out.println("FIPS mode not available: " + e.getMessage());
            fipsAvailable = false;
        }
    }

    // ========================================
    // FIPS-Approved Algorithm Tests
    // ========================================

    @Test
    public void testFIPS_AES128_CBC_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-128-CBC", 16, 16, true);
    }

    @Test
    public void testFIPS_AES192_CBC_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-192-CBC", 24, 16, true);
    }

    @Test
    public void testFIPS_AES256_CBC_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-256-CBC", 32, 16, true);
    }

    @Test
    public void testFIPS_AES128_CTR_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-128-CTR", 16, 16, false);
    }

    @Test
    public void testFIPS_AES256_CTR_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-256-CTR", 32, 16, false);
    }

    @Test
    public void testFIPS_AES128_ECB_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-128-ECB", 16, 0, true);
    }

    @Test
    public void testFIPS_AES128_OFB_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-128-OFB", 16, 16, false);
    }

    @Test
    public void testFIPS_AES128_CFB_Approved() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        testFIPSCipherRoundTrip("AES-128-CFB", 16, 16, false);
    }

    // ========================================
    // Non-FIPS Algorithm Rejection Tests
    // ========================================

    // DES and 3DES tests removed - DES not yet implemented in OpenSSL native code

    @Test
    public void testFIPS_ChaCha20_Rejected() {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        
        // ChaCha20 is not FIPS-approved - should fail in FIPS mode
        boolean exceptionThrown = false;
        try {
            long cipherId = fipsAdapter.CIPHER_create("ChaCha20");
            fipsAdapter.CIPHER_delete(cipherId); // Cleanup if it somehow succeeded
        } catch (Exception e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "ChaCha20 should be rejected in FIPS mode");
    }

    @Test
    public void testFIPS_RC4_Rejected() {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        
        // RC4 is not FIPS-approved - should fail in FIPS mode
        boolean exceptionThrown = false;
        try {
            long cipherId = fipsAdapter.CIPHER_create("RC4");
            fipsAdapter.CIPHER_delete(cipherId); // Cleanup if it somehow succeeded
        } catch (Exception e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "RC4 should be rejected in FIPS mode");
    }

    // ========================================
    // FIPS Context Isolation Tests
    // ========================================

    @Test
    public void testFIPSContextIsolation() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(16, 0x10);
        byte[] iv = sequentialBytes(16, 0x20);
        byte[] plaintext = "FIPS context isolation test".getBytes(StandardCharsets.UTF_8);

        // Create multiple cipher contexts to verify isolation
        long ctx1 = fipsAdapter.CIPHER_create("AES-128-CBC");
        long ctx2 = fipsAdapter.CIPHER_create("AES-128-CBC");
        
        try {
            assertNotEquals(ctx1, ctx2, "Different cipher contexts should have different IDs");
            
            // Initialize both contexts
            fipsAdapter.CIPHER_init(ctx1, 1, 1, key, iv);
            fipsAdapter.CIPHER_init(ctx2, 1, 1, key, iv);
            
            // Encrypt with both - should produce same result (same key/IV)
            byte[] cipher1 = new byte[plaintext.length + 32];
            byte[] cipher2 = new byte[plaintext.length + 32];
            
            int len1 = fipsAdapter.CIPHER_encryptUpdate(ctx1, plaintext, 0, plaintext.length, cipher1, 0, false);
            len1 += fipsAdapter.CIPHER_encryptFinal(ctx1, null, 0, 0, cipher1, len1, false);
            
            int len2 = fipsAdapter.CIPHER_encryptUpdate(ctx2, plaintext, 0, plaintext.length, cipher2, 0, false);
            len2 += fipsAdapter.CIPHER_encryptFinal(ctx2, null, 0, 0, cipher2, len2, false);
            
            assertEquals(len1, len2, "Ciphertext lengths should match");
            assertArrayEquals(Arrays.copyOf(cipher1, len1), Arrays.copyOf(cipher2, len2),
                    "Same key/IV should produce same ciphertext");
        } finally {
            fipsAdapter.CIPHER_delete(ctx1);
            fipsAdapter.CIPHER_delete(ctx2);
        }
    }

    @Test
    public void testFIPSMultipleOperationsOnSameContext() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(16, 0x30);
        byte[] iv = sequentialBytes(16, 0x40);
        byte[] plaintext1 = "First message".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext2 = "Second message".getBytes(StandardCharsets.UTF_8);

        long cipherId = fipsAdapter.CIPHER_create("AES-128-CBC");
        try {
            // First encryption
            fipsAdapter.CIPHER_init(cipherId, 1, 1, key, iv);
            byte[] cipher1 = new byte[plaintext1.length + 32];
            int len1 = fipsAdapter.CIPHER_encryptUpdate(cipherId, plaintext1, 0, plaintext1.length, cipher1, 0, false);
            len1 += fipsAdapter.CIPHER_encryptFinal(cipherId, null, 0, 0, cipher1, len1, false);
            
            // Reinitialize for second encryption
            fipsAdapter.CIPHER_init(cipherId, 1, 1, key, iv);
            byte[] cipher2 = new byte[plaintext2.length + 32];
            int len2 = fipsAdapter.CIPHER_encryptUpdate(cipherId, plaintext2, 0, plaintext2.length, cipher2, 0, false);
            len2 += fipsAdapter.CIPHER_encryptFinal(cipherId, null, 0, 0, cipher2, len2, false);
            
            // Both operations should succeed
            assertTrue(len1 > 0, "First encryption should produce output");
            assertTrue(len2 > 0, "Second encryption should produce output");
        } finally {
            fipsAdapter.CIPHER_delete(cipherId);
        }
    }

    // ========================================
    // FIPS Streaming Operations
    // ========================================

    @Test
    public void testFIPS_StreamingEncryptDecrypt() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(32, 0x50);
        byte[] iv = sequentialBytes(16, 0x60);
        byte[] plaintext = "FIPS streaming test with multiple update calls for AES-256-CBC".getBytes(StandardCharsets.UTF_8);

        // Encrypt with streaming
        long encryptCtx = fipsAdapter.CIPHER_create("AES-256-CBC");
        byte[] ciphertext = null;
        int cipherLen = 0;
        try {
            fipsAdapter.CIPHER_init(encryptCtx, 1, 1, key, iv);

            byte[] tempCipher = new byte[plaintext.length + 32];
            int offset = 0;

            // Update in chunks
            int chunk1 = 25;
            int len1 = fipsAdapter.CIPHER_encryptUpdate(encryptCtx, plaintext, 0, chunk1, tempCipher, offset, false);
            offset += len1;

            int chunk2 = plaintext.length - chunk1;
            int len2 = fipsAdapter.CIPHER_encryptUpdate(encryptCtx, plaintext, chunk1, chunk2, tempCipher, offset, false);
            offset += len2;

            int len3 = fipsAdapter.CIPHER_encryptFinal(encryptCtx, null, 0, 0, tempCipher, offset, false);
            offset += len3;

            cipherLen = offset;
            ciphertext = Arrays.copyOf(tempCipher, cipherLen);
        } finally {
            fipsAdapter.CIPHER_delete(encryptCtx);
        }

        // Decrypt with streaming
        long decryptCtx = fipsAdapter.CIPHER_create("AES-256-CBC");
        try {
            fipsAdapter.CIPHER_init(decryptCtx, 0, 1, key, iv);

            byte[] tempPlain = new byte[cipherLen];
            int offset = 0;

            // Update in chunks
            int chunk1 = 32; // Two blocks
            int len1 = fipsAdapter.CIPHER_decryptUpdate(decryptCtx, ciphertext, 0, chunk1, tempPlain, offset, false);
            offset += len1;

            int chunk2 = cipherLen - chunk1;
            int len2 = fipsAdapter.CIPHER_decryptUpdate(decryptCtx, ciphertext, chunk1, chunk2, tempPlain, offset, false);
            offset += len2;

            int len3 = fipsAdapter.CIPHER_decryptFinal(decryptCtx, null, 0, 0, tempPlain, offset, false);
            offset += len3;

            byte[] decrypted = Arrays.copyOf(tempPlain, offset);
            assertArrayEquals(plaintext, decrypted, "FIPS streaming round-trip should match");
        } finally {
            fipsAdapter.CIPHER_delete(decryptCtx);
        }
    }

    // ========================================
    // FIPS Edge Cases
    // ========================================

    @Test
    public void testFIPS_LargeData() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(32, 0x70);
        byte[] iv = sequentialBytes(16, 0x80);
        byte[] largePlaintext = new byte[50000]; // 50KB
        Arrays.fill(largePlaintext, (byte) 0xEF);

        testFIPSCipherRoundTripWithData("AES-256-CBC", 32, 16, true, largePlaintext);
    }

    @Test
    public void testFIPS_ZeroLengthInput() throws Exception {
        Assumptions.assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(16, 0x90);
        byte[] iv = sequentialBytes(16, 0xA0);
        byte[] emptyInput = new byte[0];

        long cipherId = fipsAdapter.CIPHER_create("AES-128-CTR");
        try {
            fipsAdapter.CIPHER_init(cipherId, 1, 0, key, iv); // NoPadding

            byte[] output = new byte[16];
            int len = fipsAdapter.CIPHER_encryptUpdate(cipherId, emptyInput, 0, 0, output, 0, false);
            len += fipsAdapter.CIPHER_encryptFinal(cipherId, null, 0, 0, output, len, false);

            assertEquals(0, len, "Zero-length input should produce zero-length output in FIPS mode");
        } finally {
            fipsAdapter.CIPHER_delete(cipherId);
        }
    }

    // ========================================
    // Helper Methods
    // ========================================

    private void testFIPSCipherRoundTrip(String algorithm, int keyLen, int ivLen, boolean usePadding) throws Exception {
        testFIPSCipherRoundTripWithData(algorithm, keyLen, ivLen, usePadding, TEST_PLAINTEXT);
    }

    private void testFIPSCipherRoundTripWithData(String algorithm, int keyLen, int ivLen, boolean usePadding, byte[] plaintext) throws Exception {
        byte[] key = sequentialBytes(keyLen, 0x11);
        byte[] iv = ivLen > 0 ? sequentialBytes(ivLen, 0x22) : null;

        // Encrypt
        long encryptCtx = fipsAdapter.CIPHER_create(algorithm);
        byte[] ciphertext = null;
        int cipherLen = 0;
        try {
            int paddingMode = usePadding ? 1 : 0;
            fipsAdapter.CIPHER_init(encryptCtx, 1, paddingMode, key, iv);

            byte[] tempCipher = new byte[plaintext.length + 32];
            int len1 = fipsAdapter.CIPHER_encryptUpdate(encryptCtx, plaintext, 0, plaintext.length, tempCipher, 0, false);
            int len2 = fipsAdapter.CIPHER_encryptFinal(encryptCtx, null, 0, 0, tempCipher, len1, false);
            cipherLen = len1 + len2;
            ciphertext = Arrays.copyOf(tempCipher, cipherLen);

            assertTrue(cipherLen > 0, "Ciphertext length should be positive");
        } finally {
            fipsAdapter.CIPHER_delete(encryptCtx);
        }

        // Decrypt
        long decryptCtx = fipsAdapter.CIPHER_create(algorithm);
        try {
            int paddingMode = usePadding ? 1 : 0;
            fipsAdapter.CIPHER_init(decryptCtx, 0, paddingMode, key, iv);

            byte[] tempPlain = new byte[cipherLen];
            int len1 = fipsAdapter.CIPHER_decryptUpdate(decryptCtx, ciphertext, 0, cipherLen, tempPlain, 0, false);
            int len2 = fipsAdapter.CIPHER_decryptFinal(decryptCtx, null, 0, 0, tempPlain, len1, false);
            int plainLen = len1 + len2;

            byte[] decrypted = Arrays.copyOf(tempPlain, plainLen);
            assertArrayEquals(plaintext, decrypted,
                    String.format("FIPS round-trip failed for %s (keyLen=%d, ivLen=%d, padding=%b)",
                            algorithm, keyLen, ivLen, usePadding));
        } finally {
            fipsAdapter.CIPHER_delete(decryptCtx);
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


