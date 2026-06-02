/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openssl;

import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapterNonFIPS;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLHKDFNative {

    private static NativeOpenSSLAdapterNonFIPS nonFipsAdapter;

    private static final byte[] SALT =
            "hkdf-salt".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IKM =
            "hkdf-input-key-material".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO =
            "hkdf-info".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public void setUp() {
        try {
            nonFipsAdapter = NativeOpenSSLAdapterNonFIPS.getInstance();
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL adapter: " + e.getMessage());
        }
    }

    @Test
    public void testHkdfExtractExpandDeriveLifecycle() throws Exception {
        long hkdfId = nonFipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");

        byte[] prk = nonFipsAdapter.HKDF_extract(hkdfId, SALT, SALT.length, IKM, IKM.length);
        assertNotNull(prk, "HKDF extract output should not be null");
        assertEquals(32, prk.length, "HKDF extract with SHA-256 should produce 32-byte PRK");

        byte[] okmExpand = nonFipsAdapter.HKDF_expand(hkdfId, prk, prk.length, INFO, INFO.length, 42);
        assertNotNull(okmExpand, "HKDF expand output should not be null");
        assertEquals(42, okmExpand.length, "HKDF expand output length should match request");

        byte[] okmDerive = nonFipsAdapter.HKDF_derive(hkdfId, SALT, SALT.length, IKM, IKM.length,
                INFO, INFO.length, 42);
        assertNotNull(okmDerive, "HKDF derive output should not be null");
        assertEquals(42, okmDerive.length, "HKDF derive output length should match request");
    }

    @Test
    public void testHkdfDeterministicForSameInputs() throws Exception {
        long hkdfId = nonFipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");

        byte[] prk = nonFipsAdapter.HKDF_extract(hkdfId, SALT, SALT.length, IKM, IKM.length);
        byte[] okmExpand1 = nonFipsAdapter.HKDF_expand(hkdfId, prk, prk.length, INFO, INFO.length, 42);
        byte[] okmExpand2 = nonFipsAdapter.HKDF_expand(hkdfId, prk, prk.length, INFO, INFO.length, 42);
        byte[] okmDerive1 = nonFipsAdapter.HKDF_derive(hkdfId, SALT, SALT.length, IKM, IKM.length,
                INFO, INFO.length, 42);
        byte[] okmDerive2 = nonFipsAdapter.HKDF_derive(hkdfId, SALT, SALT.length, IKM, IKM.length,
                INFO, INFO.length, 42);

        assertArrayEquals(okmExpand1, okmExpand2,
                "HKDF expand should be deterministic for same inputs");
        assertArrayEquals(okmDerive1, okmDerive2,
                "HKDF derive should be deterministic for same inputs");
    }

    @Test
    public void testHkdfOptionalSaltAndInfoHandling() throws Exception {
        long hkdfId = nonFipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");

        byte[] prkNoSalt = nonFipsAdapter.HKDF_extract(hkdfId, null, 0, IKM, IKM.length);
        assertNotNull(prkNoSalt, "HKDF extract without salt should not be null");
        assertEquals(32, prkNoSalt.length, "HKDF extract without salt should still match digest size");

        byte[] okmNoInfo = nonFipsAdapter.HKDF_expand(hkdfId, prkNoSalt, prkNoSalt.length, null, 0, 16);
        assertNotNull(okmNoInfo, "HKDF expand without info should not be null");
        assertEquals(16, okmNoInfo.length, "HKDF expand without info should honor requested length");

        byte[] okmDerivedNoSaltInfo = nonFipsAdapter.HKDF_derive(hkdfId, null, 0, IKM, IKM.length,
                null, 0, 16);
        assertNotNull(okmDerivedNoSaltInfo, "HKDF derive without salt and info should not be null");
        assertEquals(16, okmDerivedNoSaltInfo.length,
                "HKDF derive without salt and info should honor requested length");
    }

    @Test
    public void testHkdfMultipleAlgorithms() throws Exception {
        long sha256Id = nonFipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, sha256Id, "SHA-256 HKDF id should match stateless sentinel");
        byte[] prk256 = nonFipsAdapter.HKDF_extract(sha256Id, SALT, SALT.length, IKM, IKM.length);
        assertEquals(32, prk256.length, "SHA-256 PRK length should be 32 bytes");
        byte[] okm256 = nonFipsAdapter.HKDF_expand(sha256Id, prk256, prk256.length, INFO, INFO.length, 32);
        assertEquals(32, okm256.length, "SHA-256 OKM length should be 32 bytes");

        long sha512Id = nonFipsAdapter.HKDF_create("SHA-512");
        assertEquals(1L, sha512Id, "SHA-512 HKDF id should match stateless sentinel");
        byte[] prk512 = nonFipsAdapter.HKDF_extract(sha512Id, SALT, SALT.length, IKM, IKM.length);
        assertEquals(64, prk512.length, "SHA-512 PRK length should be 64 bytes");
        byte[] okm512 = nonFipsAdapter.HKDF_expand(sha512Id, prk512, prk512.length, INFO, INFO.length, 32);
        assertEquals(32, okm512.length, "SHA-512 OKM length should be 32 bytes");

        assertFalse(Arrays.equals(okm256, okm512),
                "Different HKDF algorithms should not produce the same output");
    }
}

