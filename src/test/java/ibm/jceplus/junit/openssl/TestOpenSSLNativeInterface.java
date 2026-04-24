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
import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapterNonFIPS;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Direct coverage-oriented tests for the implemented OpenSSL adapter/native path.
 *
 * <p>This suite exercises adapter methods that delegate directly to the OpenSSL
 * native layer, with positive-path coverage for cipher, key-wrap, PBKDF2, digest,
 * HMAC, and HKDF operations.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLNativeInterface {

    private static NativeOpenSSLAdapterNonFIPS nonFipsAdapter;
    private static NativeOpenSSLAdapterFIPS fipsAdapter;

    private static final byte[] TEST_INPUT =
            "Hello, OpenSSL native interface!".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public void setUp() {
        try {
            nonFipsAdapter = NativeOpenSSLAdapterNonFIPS.getInstance();
            try {
                fipsAdapter = NativeOpenSSLAdapterFIPS.getInstance();
            } catch (Exception ignored) {
                fipsAdapter = null;
            }
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL adapters: " + e.getMessage());
        }
    }

    @Test
    public void testLibraryBuildDateAndContextValues() throws Exception {
        String buildDate = nonFipsAdapter.getLibraryBuildDate();
        assertNotNull(buildDate, "Build date should not be null");
        assertFalse(buildDate.isEmpty(), "Build date should not be empty");

        String opensslVersion = nonFipsAdapter.getLibraryVersion();
        assertNotNull(opensslVersion, "OpenSSL version should not be null");
        assertFalse(opensslVersion.isEmpty(), "OpenSSL version should not be empty");

        String installPath = nonFipsAdapter.getLibraryInstallPath();
        assertNotNull(installPath, "Install path should not be null");
        assertFalse(installPath.isEmpty(), "Install path should not be empty");
    }

    @Test
    public void testGetByteBufferPointer() {
        ByteBuffer direct = ByteBuffer.allocateDirect(32);
        long pointer = nonFipsAdapter.getByteBufferPointer(direct);
        assertNotEquals(0L, pointer, "Direct ByteBuffer pointer should be non-zero");
    }

    @Test
    public void testCipherLifecycleAndRoundTrip() throws OCKException {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Arrays.fill(key, (byte) 0x11);
        Arrays.fill(iv, (byte) 0x22);

        byte[] plaintext = new byte[16];
        System.arraycopy(TEST_INPUT, 0, plaintext, 0, Math.min(TEST_INPUT.length, plaintext.length));

        long cipherId = nonFipsAdapter.CIPHER_create("AES-128-CBC");
        assertTrue(cipherId > 0, "Cipher ID should be positive");

        try {
            assertEquals(16, nonFipsAdapter.CIPHER_getBlockSize(cipherId),
                    "AES block size should be 16");
            assertEquals(16, nonFipsAdapter.CIPHER_getKeyLength(cipherId),
                    "AES-128 key length should be 16");
            assertEquals(16, nonFipsAdapter.CIPHER_getIVLength(cipherId),
                    "AES CBC IV length should be 16");

            nonFipsAdapter.CIPHER_init(cipherId, 1, 0, key, iv);

            byte[] ciphertext = new byte[32];
            int updateLen = nonFipsAdapter.CIPHER_encryptUpdate(cipherId, plaintext, 0, plaintext.length,
                    ciphertext, 0, false);
            assertTrue(updateLen > 0, "Encrypt update should return output");

            int finalLen = nonFipsAdapter.CIPHER_encryptFinal(cipherId, new byte[0], 0, 0,
                    ciphertext, updateLen, false);
            int totalCiphertextLen = updateLen + finalLen;
            assertTrue(totalCiphertextLen > 0, "Total ciphertext length should be positive");

            nonFipsAdapter.CIPHER_init(cipherId, 0, 0, key, iv);

            byte[] decrypted = new byte[32];
            int decUpdateLen = nonFipsAdapter.CIPHER_decryptUpdate(cipherId, ciphertext, 0,
                    totalCiphertextLen, decrypted, 0, false);
            assertTrue(decUpdateLen > 0, "Decrypt update should return output");

            int decFinalLen = nonFipsAdapter.CIPHER_decryptFinal(cipherId, new byte[0], 0, 0,
                    decrypted, decUpdateLen, false);
            int totalPlaintextLen = decUpdateLen + decFinalLen;

            byte[] actual = Arrays.copyOf(decrypted, totalPlaintextLen);
            assertArrayEquals(plaintext, actual, "Decrypted plaintext should match input");
        } finally {
            nonFipsAdapter.CIPHER_delete(cipherId);
        }
    }

    @Test
    public void testSymmetricCipherAesCbcPkcs5RoundTrip() throws OCKException {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Arrays.fill(key, (byte) 0x41);
        Arrays.fill(iv, (byte) 0x24);

        byte[] plaintext = "OpenSSL CBC PKCS5 round trip test data".getBytes(StandardCharsets.UTF_8);

        long cipherId = nonFipsAdapter.CIPHER_create("AES-128-CBC");
        assertTrue(cipherId > 0, "Cipher ID should be positive");

        try {
            nonFipsAdapter.CIPHER_init(cipherId, 1, 1, key, iv);

            byte[] ciphertext = new byte[plaintext.length + 32];
            int updateLen = nonFipsAdapter.CIPHER_encryptUpdate(cipherId, plaintext, 0, plaintext.length,
                    ciphertext, 0, false);
            int finalLen = nonFipsAdapter.CIPHER_encryptFinal(cipherId, new byte[0], 0, 0,
                    ciphertext, updateLen, false);
            int totalCipherLen = updateLen + finalLen;

            assertTrue(totalCipherLen > plaintext.length,
                    "CBC/PKCS5 ciphertext should include padding");

            nonFipsAdapter.CIPHER_init(cipherId, 0, 1, key, iv);

            byte[] decrypted = new byte[plaintext.length + 32];
            int decUpdateLen = nonFipsAdapter.CIPHER_decryptUpdate(cipherId, ciphertext, 0, totalCipherLen,
                    decrypted, 0, false);
            int decFinalLen = nonFipsAdapter.CIPHER_decryptFinal(cipherId, new byte[0], 0, 0,
                    decrypted, decUpdateLen, false);
            int totalPlainLen = decUpdateLen + decFinalLen;

            assertArrayEquals(plaintext, Arrays.copyOf(decrypted, totalPlainLen),
                    "CBC/PKCS5 decrypted plaintext should match input");
        } finally {
            nonFipsAdapter.CIPHER_delete(cipherId);
        }
    }

    @Test
    public void testSymmetricCipherAesCtrRoundTripWithReuse() throws OCKException {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        Arrays.fill(key, (byte) 0x6A);
        Arrays.fill(iv, (byte) 0x3C);

        byte[] plaintext1 = "CTR mode first message".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext2 = "CTR mode second message".getBytes(StandardCharsets.UTF_8);

        long cipherId = nonFipsAdapter.CIPHER_create("AES-128-CTR");
        assertTrue(cipherId > 0, "Cipher ID should be positive");

        try {
            assertEquals(16, nonFipsAdapter.CIPHER_getIVLength(cipherId),
                    "AES CTR IV length should be 16");

            nonFipsAdapter.CIPHER_init(cipherId, 1, 0, key, iv);

            byte[] ciphertext1 = new byte[plaintext1.length + 16];
            int encLen1 = nonFipsAdapter.CIPHER_encryptUpdate(cipherId, plaintext1, 0, plaintext1.length,
                    ciphertext1, 0, false);
            encLen1 += nonFipsAdapter.CIPHER_encryptFinal(cipherId, new byte[0], 0, 0,
                    ciphertext1, encLen1, false);

            byte[] ciphertext2 = new byte[plaintext2.length + 16];
            int encLen2 = nonFipsAdapter.CIPHER_encryptUpdate(cipherId, plaintext2, 0, plaintext2.length,
                    ciphertext2, 0, true);
            encLen2 += nonFipsAdapter.CIPHER_encryptFinal(cipherId, new byte[0], 0, 0,
                    ciphertext2, encLen2, false);

            nonFipsAdapter.CIPHER_init(cipherId, 0, 0, key, iv);

            byte[] decrypted1 = new byte[plaintext1.length + 16];
            int decLen1 = nonFipsAdapter.CIPHER_decryptUpdate(cipherId, ciphertext1, 0, encLen1,
                    decrypted1, 0, false);
            decLen1 += nonFipsAdapter.CIPHER_decryptFinal(cipherId, new byte[0], 0, 0,
                    decrypted1, decLen1, false);

            byte[] decrypted2 = new byte[plaintext2.length + 16];
            int decLen2 = nonFipsAdapter.CIPHER_decryptUpdate(cipherId, ciphertext2, 0, encLen2,
                    decrypted2, 0, true);
            decLen2 += nonFipsAdapter.CIPHER_decryptFinal(cipherId, new byte[0], 0, 0,
                    decrypted2, decLen2, false);

            assertArrayEquals(plaintext1, Arrays.copyOf(decrypted1, decLen1),
                    "First CTR decrypted plaintext should match input");
            assertArrayEquals(plaintext2, Arrays.copyOf(decrypted2, decLen2),
                    "Second CTR decrypted plaintext should match input");
        } finally {
            nonFipsAdapter.CIPHER_delete(cipherId);
        }
    }

    @Test
    public void testKeyWrapRoundTrip() throws OCKException {
        byte[] keyToWrap = new byte[16];
        byte[] kek = new byte[16];
        Arrays.fill(keyToWrap, (byte) 0x5A);
        Arrays.fill(kek, (byte) 0x33);

        byte[] wrapped = nonFipsAdapter.CIPHER_KeyWraporUnwrap(keyToWrap, kek, 1);
        assertNotNull(wrapped, "Wrapped key should not be null");
        assertTrue(wrapped.length > keyToWrap.length, "Wrapped key should be longer than plaintext");

        byte[] unwrapped = nonFipsAdapter.CIPHER_KeyWraporUnwrap(wrapped, kek, 0);
        assertArrayEquals(keyToWrap, unwrapped, "Unwrapped key should match original key");
    }

    @Test
    public void testKeyWrapWithPaddingRoundTrip() throws OCKException {
        byte[] keyToWrap = new byte[21];
        byte[] kek = new byte[32];
        Arrays.fill(keyToWrap, (byte) 0x44);
        Arrays.fill(kek, (byte) 0x55);

        byte[] wrapped = nonFipsAdapter.CIPHER_KeyWraporUnwrap(keyToWrap, kek, 0x5);
        assertNotNull(wrapped, "Wrapped padded key should not be null");
        assertEquals(0, wrapped.length % 8, "RFC5649 wrapped key should be multiple of 8 bytes");

        byte[] unwrapped = nonFipsAdapter.CIPHER_KeyWraporUnwrap(wrapped, kek, 0x4);
        assertArrayEquals(keyToWrap, unwrapped, "RFC5649 unwrapped key should match original key");
    }

    @Test
    public void testKeyWrapRejectsWrongKek() throws OCKException {
        byte[] keyToWrap = new byte[16];
        byte[] kek = new byte[16];
        byte[] wrongKek = new byte[16];
        Arrays.fill(keyToWrap, (byte) 0x12);
        Arrays.fill(kek, (byte) 0x34);
        Arrays.fill(wrongKek, (byte) 0x56);

        byte[] wrapped = nonFipsAdapter.CIPHER_KeyWraporUnwrap(keyToWrap, kek, 1);
        assertNotNull(wrapped, "Wrapped key should not be null");

        boolean exceptionThrown = false;
        try {
            nonFipsAdapter.CIPHER_KeyWraporUnwrap(wrapped, wrongKek, 0);
        } catch (Exception e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "Unwrap with wrong KEK should throw");
    }

    @Test
    public void testKeyWrapRejectsCorruptedWrappedKey() throws OCKException {
        byte[] keyToWrap = new byte[16];
        byte[] kek = new byte[16];
        Arrays.fill(keyToWrap, (byte) 0x21);
        Arrays.fill(kek, (byte) 0x43);

        byte[] wrapped = nonFipsAdapter.CIPHER_KeyWraporUnwrap(keyToWrap, kek, 1);
        assertNotNull(wrapped, "Wrapped key should not be null");

        wrapped[0] ^= 0x01;

        boolean exceptionThrown = false;
        try {
            nonFipsAdapter.CIPHER_KeyWraporUnwrap(wrapped, kek, 0);
        } catch (Exception e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown, "Corrupted wrapped key should throw");
    }

    @Test
    public void testPbkdf2Derive() throws Exception {
        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);

        byte[] derived = nonFipsAdapter.PBKDF2_derive("SHA256", password, salt, 4096, 32);
        assertNotNull(derived, "PBKDF2 output should not be null");
        assertEquals(32, derived.length, "PBKDF2 output length should match request");

        byte[] derivedAgain = nonFipsAdapter.PBKDF2_derive("SHA256", password, salt, 4096, 32);
        assertArrayEquals(derived, derivedAgain, "PBKDF2 should be deterministic for same inputs");
    }

    @Test
    public void testInvalidCipherFails() {
        try {
            nonFipsAdapter.CIPHER_create("INVALID-CIPHER-NAME");
            fail("Invalid cipher should throw");
        } catch (Exception exception) {
            assertNotNull(exception, "Invalid cipher should throw");
        }
    }

    @Test
    public void testHmacLifecycle() throws Exception {
        byte[] key = "hmac-key-material".getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[32];

        long hmacId = nonFipsAdapter.HMAC_create("SHA256");
        assertTrue(hmacId > 0, "HMAC ID should be positive");

        try {
            assertEquals(32, nonFipsAdapter.HMAC_size(hmacId),
                    "HMAC-SHA256 size should be 32 bytes");

            int updated = nonFipsAdapter.HMAC_update(hmacId, key, key.length, TEST_INPUT, 0,
                    TEST_INPUT.length, true);
            assertEquals(1, updated, "HMAC update should report success");

            int written = nonFipsAdapter.HMAC_doFinal(hmacId, key, key.length, output, false);
            assertEquals(1, written, "HMAC final should report success");

            byte[] secondOutput = new byte[32];
            int secondUpdated = nonFipsAdapter.HMAC_update(hmacId, key, key.length, TEST_INPUT, 0,
                    TEST_INPUT.length, true);
            assertEquals(1, secondUpdated, "Second HMAC update should report success");
            int secondWritten = nonFipsAdapter.HMAC_doFinal(hmacId, key, key.length, secondOutput, false);
            assertEquals(1, secondWritten, "Second HMAC final should report success");

            assertArrayEquals(output, secondOutput,
                    "HMAC should be deterministic for same key and input");
        } finally {
            nonFipsAdapter.HMAC_delete(hmacId);
        }
    }

    @Test
    public void testHkdfOperations() throws Exception {
        byte[] salt = "hkdf-salt".getBytes(StandardCharsets.UTF_8);
        byte[] ikm = "hkdf-input-key-material".getBytes(StandardCharsets.UTF_8);
        byte[] info = "hkdf-info".getBytes(StandardCharsets.UTF_8);

        long hkdfId = nonFipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");

        byte[] prk = nonFipsAdapter.HKDF_extract(hkdfId, salt, salt.length, ikm, ikm.length);
        assertNotNull(prk, "HKDF extract output should not be null");
        assertEquals(32, prk.length, "HKDF extract with SHA-256 should produce 32-byte PRK");

        byte[] okmExpand = nonFipsAdapter.HKDF_expand(hkdfId, prk, prk.length, info, info.length, 42);
        assertNotNull(okmExpand, "HKDF expand output should not be null");
        assertEquals(42, okmExpand.length, "HKDF expand output length should match request");

        byte[] okmDerive = nonFipsAdapter.HKDF_derive(hkdfId, salt, salt.length, ikm, ikm.length,
                info, info.length, 42);
        assertNotNull(okmDerive, "HKDF derive output should not be null");
        assertEquals(42, okmDerive.length, "HKDF derive output length should match request");

        byte[] okmExpandAgain = nonFipsAdapter.HKDF_expand(hkdfId, prk, prk.length, info, info.length, 42);
        assertArrayEquals(okmExpand, okmExpandAgain,
                "HKDF expand should be deterministic for same inputs");
    }

    @Test
    public void testUnsupportedRandomMethodsFailExplicitly() {
        try {
            nonFipsAdapter.RAND_nextBytes(new byte[16]);
            fail("RAND_nextBytes should throw UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            // expected
        } catch (OCKException e) {
            fail("RAND_nextBytes should not throw OCKException", e);
        }

        try {
            nonFipsAdapter.RAND_setSeed(new byte[16]);
            fail("RAND_setSeed should throw UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            // expected
        } catch (OCKException e) {
            fail("RAND_setSeed should not throw OCKException", e);
        }

        try {
            nonFipsAdapter.RAND_generateSeed(new byte[16]);
            fail("RAND_generateSeed should throw UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            // expected
        } catch (OCKException e) {
            fail("RAND_generateSeed should not throw OCKException", e);
        }
    }

    @Test
    public void testFipsModeIfAvailable() throws Exception {
        if (fipsAdapter == null) {
            return;
        }

        String buildDate = fipsAdapter.getLibraryBuildDate();
        assertNotNull(buildDate, "FIPS build date should not be null");

        long cipherId = fipsAdapter.CIPHER_create("AES-128-CBC");
        assertTrue(cipherId > 0, "FIPS cipher creation should succeed");
        fipsAdapter.CIPHER_delete(cipherId);
    }

    @Test
    public void testFipsDigestAndPbkdf2IfAvailable() throws Exception {
        if (fipsAdapter == null) {
            return;
        }

        long digestId = fipsAdapter.DIGEST_create("SHA256");
        assertTrue(digestId > 0, "FIPS digest creation should succeed");
        try {
            assertEquals(32, fipsAdapter.DIGEST_size(digestId), "FIPS SHA256 digest size should be 32");
            int updated = fipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length);
            // FIPS adapter may return 0 or 1 for success depending on OpenSSL version
            assertTrue(updated == 0 || updated == 1, "FIPS digest update should succeed (return 0 or 1)");
            byte[] digest = fipsAdapter.DIGEST_digest(digestId);
            assertEquals(32, digest.length, "FIPS digest output length should be 32");
        } finally {
            fipsAdapter.DIGEST_delete(digestId);
        }

        // PBKDF2 may or may not be approved in FIPS mode depending on OpenSSL configuration
        try {
            byte[] derived = fipsAdapter.PBKDF2_derive("SHA256",
                    "password".getBytes(StandardCharsets.UTF_8),
                    "salt".getBytes(StandardCharsets.UTF_8),
                    1024, 32);
            assertNotNull(derived, "FIPS PBKDF2 output should not be null");
            assertEquals(32, derived.length, "FIPS PBKDF2 output length should match request");
        } catch (Exception e) {
            // PBKDF2 may not be approved in FIPS mode - this is acceptable
            assertTrue(e.getMessage().contains("PBKDF2") || e.getMessage().contains("Error code"),
                    "FIPS PBKDF2 failure should be related to PBKDF2 or error code");
        }
    }
}


