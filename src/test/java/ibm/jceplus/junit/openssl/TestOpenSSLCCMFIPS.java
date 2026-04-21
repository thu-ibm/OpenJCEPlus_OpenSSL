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

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * FIPS mode tests for OpenSSL CCM operations.
 * Tests the same functionality as TestOpenSSLCCMNative but using FIPS adapter.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLCCMFIPS {

    private static NativeOpenSSLAdapterFIPS fipsAdapter;
    private static boolean fipsAvailable = false;

    @BeforeAll
    public void setUp() {
        try {
            fipsAdapter = NativeOpenSSLAdapterFIPS.getInstance();
            fipsAvailable = true;
        } catch (Exception e) {
            System.out.println("FIPS mode not available, tests will be skipped: " + e.getMessage());
            fipsAvailable = false;
        }
    }

    @Test
    public void testCcmEncryptDecryptRoundTrip() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(16, 0x10);
        byte[] nonce = sequentialBytes(13, 0x20);
        byte[] aad = "ccm-aad-fips".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "OpenSSL FIPS CCM round-trip test".getBytes(StandardCharsets.UTF_8);
        int tagLen = 16;
        byte[] ciphertext = new byte[plaintext.length + tagLen];
        byte[] decrypted = new byte[plaintext.length];

        int rc = fipsAdapter.do_CCM_encrypt(nonce, nonce.length, key, key.length, aad, aad.length,
                plaintext, plaintext.length, ciphertext, ciphertext.length, tagLen);
        assertEquals(0, rc, "CCM encrypt should succeed");

        int decRc = fipsAdapter.do_CCM_decrypt(nonce, nonce.length, key, key.length, aad, aad.length,
                ciphertext, ciphertext.length, decrypted, decrypted.length, tagLen);
        assertEquals(0, decRc, "CCM decrypt should succeed");
        assertArrayEquals(plaintext, decrypted, "CCM round-trip plaintext should match");
    }

    @Test
    public void testCcmDecryptFailsWithTamperedTag() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(16, 0x30);
        byte[] nonce = sequentialBytes(13, 0x40);
        byte[] aad = "tamper-aad-fips".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Tampered FIPS CCM tag must fail".getBytes(StandardCharsets.UTF_8);
        int tagLen = 16;
        byte[] ciphertext = new byte[plaintext.length + tagLen];

        int rc = fipsAdapter.do_CCM_encrypt(nonce, nonce.length, key, key.length, aad, aad.length,
                plaintext, plaintext.length, ciphertext, ciphertext.length, tagLen);
        assertEquals(0, rc, "CCM encrypt should succeed");

        // Tamper with the ciphertext
        ciphertext[0] ^= 0x01;

        byte[] output = new byte[plaintext.length];
        boolean exceptionThrown = false;
        try {
            fipsAdapter.do_CCM_decrypt(nonce, nonce.length, key, key.length, aad, aad.length,
                    ciphertext, ciphertext.length, output, output.length, tagLen);
        } catch (OCKException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "Tampered CCM decrypt should throw");
    }

    @Test
    public void testCcmVariousTagLengths() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] key = sequentialBytes(16, 0x50);
        byte[] nonce = sequentialBytes(13, 0x60);
        byte[] plaintext = "CCM tag length test".getBytes(StandardCharsets.UTF_8);
        int[] tagLengths = {4, 6, 8, 10, 12, 14, 16};

        for (int tagLen : tagLengths) {
            byte[] ciphertext = new byte[plaintext.length + tagLen];
            byte[] decrypted = new byte[plaintext.length];

            int rc = fipsAdapter.do_CCM_encrypt(nonce, nonce.length, key, key.length, null, 0,
                    plaintext, plaintext.length, ciphertext, ciphertext.length, tagLen);
            assertEquals(0, rc, "CCM encrypt should succeed with tag length " + tagLen);

            int decRc = fipsAdapter.do_CCM_decrypt(nonce, nonce.length, key, key.length, null, 0,
                    ciphertext, ciphertext.length, decrypted, decrypted.length, tagLen);
            assertEquals(0, decRc, "CCM decrypt should succeed with tag length " + tagLen);
            assertArrayEquals(plaintext, decrypted, "CCM plaintext should match with tag length " + tagLen);
        }
    }

    @Test
    public void testCcmDifferentKeySizes() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] nonce = sequentialBytes(13, 0x70);
        byte[] aad = "key-size-test".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "CCM supports AES-128 and AES-256".getBytes(StandardCharsets.UTF_8);
        int tagLen = 12;

        // Test AES-128
        byte[] key128 = sequentialBytes(16, 0x80);
        byte[] ciphertext128 = new byte[plaintext.length + tagLen];
        byte[] decrypted128 = new byte[plaintext.length];

        int rc128 = fipsAdapter.do_CCM_encrypt(nonce, nonce.length, key128, key128.length, aad, aad.length,
                plaintext, plaintext.length, ciphertext128, ciphertext128.length, tagLen);
        assertEquals(0, rc128, "CCM encrypt with AES-128 should succeed");

        int decRc128 = fipsAdapter.do_CCM_decrypt(nonce, nonce.length, key128, key128.length, aad, aad.length,
                ciphertext128, ciphertext128.length, decrypted128, decrypted128.length, tagLen);
        assertEquals(0, decRc128, "CCM decrypt with AES-128 should succeed");
        assertArrayEquals(plaintext, decrypted128, "CCM AES-128 plaintext should match");

        // Test AES-256
        byte[] key256 = sequentialBytes(32, 0x90);
        byte[] ciphertext256 = new byte[plaintext.length + tagLen];
        byte[] decrypted256 = new byte[plaintext.length];

        int rc256 = fipsAdapter.do_CCM_encrypt(nonce, nonce.length, key256, key256.length, aad, aad.length,
                plaintext, plaintext.length, ciphertext256, ciphertext256.length, tagLen);
        assertEquals(0, rc256, "CCM encrypt with AES-256 should succeed");

        int decRc256 = fipsAdapter.do_CCM_decrypt(nonce, nonce.length, key256, key256.length, aad, aad.length,
                ciphertext256, ciphertext256.length, decrypted256, decrypted256.length, tagLen);
        assertEquals(0, decRc256, "CCM decrypt with AES-256 should succeed");
        assertArrayEquals(plaintext, decrypted256, "CCM AES-256 plaintext should match");
    }

    private static byte[] sequentialBytes(int len, int start) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (start + i);
        }
        return out;
    }
}

