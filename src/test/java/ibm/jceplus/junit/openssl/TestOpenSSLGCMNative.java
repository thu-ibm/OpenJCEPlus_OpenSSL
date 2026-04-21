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

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLGCMNative {

    private static NativeOpenSSLAdapterNonFIPS nonFipsAdapter;

    @BeforeAll
    public void setUp() {
        try {
            nonFipsAdapter = NativeOpenSSLAdapterNonFIPS.getInstance();
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL adapter: " + e.getMessage());
        }
    }

    @Test
    public void testGcmEncryptDecryptRoundTripWithAad() throws Exception {
        byte[] key = sequentialBytes(16, 0x10);
        byte[] iv = sequentialBytes(12, 0x21);
        byte[] aad = "gcm-aad".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "OpenSSL direct native GCM round-trip".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length];
        byte[] tag = new byte[16];
        byte[] decrypted = new byte[plaintext.length];

        long gcmCtx = nonFipsAdapter.create_GCM_context();
        assertTrue(gcmCtx > 0, "GCM context should be positive");

        try {
            int rc = nonFipsAdapter.do_GCM_encrypt(gcmCtx, key, key.length, iv, iv.length,
                    plaintext, 0, plaintext.length, ciphertext, 0, aad, aad.length, tag, 16);
            assertEquals(0, rc, "GCM encrypt should succeed");

            // Combine ciphertext and tag for decrypt
            byte[] combined = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);

            int decRc = nonFipsAdapter.do_GCM_decrypt(gcmCtx, key, key.length, iv, iv.length,
                    combined, 0, plaintext.length, decrypted, 0, aad, aad.length, 16);
            assertEquals(0, decRc, "GCM decrypt should succeed");
            assertArrayEquals(plaintext, decrypted, "GCM round-trip plaintext should match");
        } finally {
            nonFipsAdapter.free_GCM_ctx(gcmCtx);
        }
    }

    @Test
    public void testGcmUpdateFlowRoundTrip() throws Exception {
        byte[] key = sequentialBytes(16, 0x31);
        byte[] iv = sequentialBytes(12, 0x41);
        byte[] aad = "streaming-aad".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Streaming GCM update path validation payload".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length + 16];
        byte[] tag = new byte[16];
        byte[] combinedCiphertext = new byte[plaintext.length + 16];
        byte[] decrypted = new byte[plaintext.length];

        long encryptCtx = nonFipsAdapter.create_GCM_context();
        long decryptCtx = nonFipsAdapter.create_GCM_context();
        assertTrue(encryptCtx > 0, "Encrypt GCM context should be positive");
        assertTrue(decryptCtx > 0, "Decrypt GCM context should be positive");

        try {
            assertEquals(0, nonFipsAdapter.do_GCM_InitForUpdateEncrypt(encryptCtx, key, key.length, iv, iv.length,
                    aad, aad.length), "GCM update encrypt init should succeed");

            int firstPlainLen = 13;
            int encLen1 = nonFipsAdapter.do_GCM_UpdForUpdateEncrypt(encryptCtx, plaintext, 0, firstPlainLen,
                    ciphertext, 0);
            int encLen2 = nonFipsAdapter.do_GCM_FinalForUpdateEncrypt(encryptCtx, key, key.length, iv, iv.length,
                    plaintext, firstPlainLen, plaintext.length - firstPlainLen, ciphertext, encLen1, null, 0,
                    tag, tag.length);

            int totalCipherLen = encLen1 + encLen2;
            assertEquals(plaintext.length, totalCipherLen, "Ciphertext length should match plaintext length");
            System.arraycopy(ciphertext, 0, combinedCiphertext, 0, totalCipherLen);
            System.arraycopy(tag, 0, combinedCiphertext, totalCipherLen, tag.length);

            assertEquals(0, nonFipsAdapter.do_GCM_InitForUpdateDecrypt(decryptCtx, key, key.length, iv, iv.length,
                    aad, aad.length), "GCM update decrypt init should succeed");

            int firstCipherLen = 9;
            int decLen1 = nonFipsAdapter.do_GCM_UpdForUpdateDecrypt(decryptCtx, combinedCiphertext, 0, firstCipherLen,
                    decrypted, 0);
            int decLen2 = nonFipsAdapter.do_GCM_FinalForUpdateDecrypt(decryptCtx, combinedCiphertext, firstCipherLen,
                    totalCipherLen - firstCipherLen, decrypted, decLen1, decrypted.length - decLen1, null, 0,
                    tag.length);

            int totalPlainLen = decLen1 + decLen2;
            assertEquals(plaintext.length, totalPlainLen, "Recovered plaintext length should match");
            assertArrayEquals(plaintext, Arrays.copyOf(decrypted, totalPlainLen),
                    "Streaming GCM decrypted plaintext should match input");
        } finally {
            nonFipsAdapter.free_GCM_ctx(encryptCtx);
            nonFipsAdapter.free_GCM_ctx(decryptCtx);
        }
    }

    @Test
    public void testGcmDecryptFailsWithTamperedTag() throws Exception {
        byte[] key = sequentialBytes(16, 0x51);
        byte[] iv = sequentialBytes(12, 0x61);
        byte[] aad = "tamper-aad".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Tampered GCM tag must fail".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length + 16];
        byte[] tag = new byte[16];

        long gcmCtx = nonFipsAdapter.create_GCM_context();
        assertTrue(gcmCtx > 0, "GCM context should be positive");

        try {
            int rc = nonFipsAdapter.do_GCM_encrypt(gcmCtx, key, key.length, iv, iv.length,
                    plaintext, 0, plaintext.length, ciphertext, 0, aad, aad.length, tag, tag.length);
            assertEquals(0, rc, "GCM encrypt should succeed");

            byte[] tamperedCombined = new byte[plaintext.length + tag.length];
            System.arraycopy(ciphertext, 0, tamperedCombined, 0, plaintext.length);
            System.arraycopy(tag, 0, tamperedCombined, plaintext.length, tag.length);
            tamperedCombined[tamperedCombined.length - 1] ^= 0x01;

            byte[] output = new byte[plaintext.length];
            boolean exceptionThrown = false;
            try {
                nonFipsAdapter.do_GCM_decrypt(gcmCtx, key, key.length, iv, iv.length,
                        tamperedCombined, 0, plaintext.length, output, 0, aad, aad.length, tag.length);
            } catch (OCKException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown, "Tampered GCM decrypt should throw");
        } finally {
            nonFipsAdapter.free_GCM_ctx(gcmCtx);
        }
    }

    @Test
    public void testGcmUpdateRejectsInvalidOffset() throws Exception {
        byte[] key = sequentialBytes(16, 0x71);
        byte[] iv = sequentialBytes(12, 0x81);
        byte[] plaintext = "offset-check".getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[plaintext.length + 16];

        long gcmCtx = nonFipsAdapter.create_GCM_context();
        assertTrue(gcmCtx > 0, "GCM context should be positive");

        try {
            assertEquals(0, nonFipsAdapter.do_GCM_InitForUpdateEncrypt(gcmCtx, key, key.length, iv, iv.length,
                    null, 0), "GCM update encrypt init should succeed");

            boolean exceptionThrown = false;
            try {
                nonFipsAdapter.do_GCM_UpdForUpdateEncrypt(gcmCtx, plaintext, plaintext.length + 1, 1,
                        output, 0);
            } catch (OCKException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown, "Invalid GCM offset should throw");
        } finally {
            nonFipsAdapter.free_GCM_ctx(gcmCtx);
        }
    }

    private static byte[] sequentialBytes(int len, int start) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (start + i);
        }
        return out;
    }
}


