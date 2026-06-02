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
public class TestOpenSSLCCMNative {

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
    public void testCcmEncryptDecryptRoundTripWithAad() throws Exception {
        byte[] key = sequentialBytes(16, 0x11);
        byte[] iv = sequentialBytes(13, 0x22);
        byte[] aad = "ccm-aad".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "OpenSSL direct native CCM round-trip".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length + 16];
        byte[] decrypted = new byte[plaintext.length];

        int rc = nonFipsAdapter.do_CCM_encrypt(iv, iv.length, key, key.length, aad, aad.length,
                plaintext, plaintext.length, ciphertext, ciphertext.length, 16);
        assertEquals(0, rc, "CCM encrypt should succeed");

        int decRc = nonFipsAdapter.do_CCM_decrypt(iv, iv.length, key, key.length, aad, aad.length,
                ciphertext, plaintext.length + 16, decrypted, decrypted.length, 16);
        assertEquals(0, decRc, "CCM decrypt should succeed");
        assertArrayEquals(plaintext, decrypted, "CCM round-trip plaintext should match");
    }

    @Test
    public void testCcmSupportsDifferentKeySizes() throws Exception {
        byte[] iv = sequentialBytes(13, 0x33);
        byte[] aad = "ccm-multi-key".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "CCM supports AES-128 and AES-256".getBytes(StandardCharsets.UTF_8);

        verifyCcmRoundTripForKey(sequentialBytes(16, 0x40), iv, aad, plaintext, 12);
        verifyCcmRoundTripForKey(sequentialBytes(32, 0x60), iv, aad, plaintext, 12);
    }

    @Test
    public void testCcmDecryptFailsWithTamperedCiphertext() throws Exception {
        byte[] key = sequentialBytes(16, 0x52);
        byte[] iv = sequentialBytes(13, 0x62);
        byte[] aad = "ccm-tamper".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Tampered CCM ciphertext must fail".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length + 16];

        int rc = nonFipsAdapter.do_CCM_encrypt(iv, iv.length, key, key.length, aad, aad.length,
                plaintext, plaintext.length, ciphertext, ciphertext.length, 16);
        assertEquals(0, rc, "CCM encrypt should succeed");

        ciphertext[0] ^= 0x01;

        byte[] output = new byte[plaintext.length];
        boolean exceptionThrown = false;
        try {
            nonFipsAdapter.do_CCM_decrypt(iv, iv.length, key, key.length, aad, aad.length,
                    ciphertext, ciphertext.length, output, output.length, 16);
        } catch (OCKException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "Tampered CCM decrypt should throw");
    }

    @Test
    public void testCcmRejectsInvalidIvLength() {
        byte[] key = sequentialBytes(16, 0x70);
        byte[] invalidIv = sequentialBytes(6, 0x01);
        byte[] aad = "bad-iv".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "invalid iv length".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length + 16];

        boolean exceptionThrown = false;
        try {
            nonFipsAdapter.do_CCM_encrypt(invalidIv, invalidIv.length, key, key.length, aad, aad.length,
                    plaintext, plaintext.length, ciphertext, ciphertext.length, 16);
        } catch (OCKException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "Invalid CCM IV length should throw");
    }

    @Test
    public void testCcmRejectsOddTagLength() {
        byte[] key = sequentialBytes(16, 0x75);
        byte[] iv = sequentialBytes(13, 0x08);
        byte[] plaintext = "odd tag length".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = new byte[plaintext.length + 15];

        boolean exceptionThrown = false;
        try {
            nonFipsAdapter.do_CCM_encrypt(iv, iv.length, key, key.length, null, 0,
                    plaintext, plaintext.length, ciphertext, ciphertext.length, 15);
        } catch (OCKException e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "Odd CCM tag length should throw");
    }

    private void verifyCcmRoundTripForKey(byte[] key, byte[] iv, byte[] aad, byte[] plaintext, int tagLen)
            throws Exception {
        byte[] ciphertext = new byte[plaintext.length + tagLen];
        byte[] decrypted = new byte[plaintext.length];

        int rc = nonFipsAdapter.do_CCM_encrypt(iv, iv.length, key, key.length, aad, aad.length,
                plaintext, plaintext.length, ciphertext, ciphertext.length, tagLen);
        assertEquals(0, rc, "CCM encrypt should succeed");

        int decRc = nonFipsAdapter.do_CCM_decrypt(iv, iv.length, key, key.length, aad, aad.length,
                ciphertext, ciphertext.length, decrypted, decrypted.length, tagLen);
        assertEquals(0, decRc, "CCM decrypt should succeed");
        assertArrayEquals(plaintext, Arrays.copyOf(decrypted, plaintext.length),
                "CCM decrypted plaintext should match");
    }

    private static byte[] sequentialBytes(int len, int start) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (start + i);
        }
        return out;
    }
}


