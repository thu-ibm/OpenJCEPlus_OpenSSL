/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openssl;

import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapterFIPS;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * FIPS mode tests for OpenSSL HKDF operations.
 * Tests the same functionality as TestOpenSSLHKDFNative but using FIPS adapter.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLHKDFFIPS {

    private static NativeOpenSSLAdapterFIPS fipsAdapter;
    private static boolean fipsAvailable = false;

    private static final byte[] TEST_IKM = "input-key-material-fips".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_SALT = "hkdf-salt-fips".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_INFO = "hkdf-info-fips".getBytes(StandardCharsets.UTF_8);

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
    public void testHkdfExtractSha256() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        byte[] prk = fipsAdapter.HKDF_extract(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length);
        
        assertNotNull(prk, "HKDF extract result should not be null");
        assertEquals(32, prk.length, "HKDF-SHA256 extract should produce 32 bytes");
    }

    @Test
    public void testHkdfExpandSha256() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        // First extract to get PRK
        byte[] prk = fipsAdapter.HKDF_extract(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length);
        
        int outputLength = 42;
        byte[] okm = fipsAdapter.HKDF_expand(hkdfId, prk, prk.length, TEST_INFO, TEST_INFO.length, outputLength);
        
        assertNotNull(okm, "HKDF expand result should not be null");
        assertEquals(outputLength, okm.length, "HKDF expand output length should match request");
    }

    @Test
    public void testHkdfDeriveSha256() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        int outputLength = 32;
        byte[] okm = fipsAdapter.HKDF_derive(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length,
                TEST_INFO, TEST_INFO.length, outputLength);
        
        assertNotNull(okm, "HKDF derive result should not be null");
        assertEquals(outputLength, okm.length, "HKDF derive output length should match request");
    }

    @Test
    public void testHkdfExtractSha512() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-512");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        byte[] prk = fipsAdapter.HKDF_extract(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length);
        
        assertNotNull(prk, "HKDF extract result should not be null");
        assertEquals(64, prk.length, "HKDF-SHA512 extract should produce 64 bytes");
    }

    @Test
    public void testHkdfConsistency() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        int outputLength = 32;
        byte[] okm1 = fipsAdapter.HKDF_derive(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length,
                TEST_INFO, TEST_INFO.length, outputLength);
        byte[] okm2 = fipsAdapter.HKDF_derive(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length,
                TEST_INFO, TEST_INFO.length, outputLength);
        
        assertArrayEquals(okm1, okm2, "HKDF should be consistent for same inputs");
    }

    @Test
    public void testHkdfDifferentInfo() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        byte[] info2 = "different-info-fips".getBytes(StandardCharsets.UTF_8);
        int outputLength = 32;
        
        byte[] okm1 = fipsAdapter.HKDF_derive(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length,
                TEST_INFO, TEST_INFO.length, outputLength);
        byte[] okm2 = fipsAdapter.HKDF_derive(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length,
                info2, info2.length, outputLength);
        
        assertFalse(java.util.Arrays.equals(okm1, okm2),
                "HKDF should differ for different info parameters");
    }

    @Test
    public void testHkdfVariousOutputLengths() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        int[] outputLengths = {16, 32, 48, 64, 128};
        
        for (int outputLength : outputLengths) {
            byte[] okm = fipsAdapter.HKDF_derive(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length,
                    TEST_INFO, TEST_INFO.length, outputLength);
            assertNotNull(okm, "HKDF result should not be null for length " + outputLength);
            assertEquals(outputLength, okm.length, "HKDF output length should match request");
        }
    }

    @Test
    public void testHkdfWithNullSalt() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        int outputLength = 32;
        byte[] okm = fipsAdapter.HKDF_derive(hkdfId, null, 0, TEST_IKM, TEST_IKM.length,
                TEST_INFO, TEST_INFO.length, outputLength);
        
        assertNotNull(okm, "HKDF should work with null salt");
        assertEquals(outputLength, okm.length, "HKDF output length should match request");
    }

    @Test
    public void testHkdfWithNullInfo() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hkdfId = fipsAdapter.HKDF_create("SHA-256");
        assertEquals(1L, hkdfId, "OpenSSL adapter should return stateless HKDF id");
        
        int outputLength = 32;
        byte[] okm = fipsAdapter.HKDF_derive(hkdfId, TEST_SALT, TEST_SALT.length, TEST_IKM, TEST_IKM.length,
                null, 0, outputLength);
        
        assertNotNull(okm, "HKDF should work with null info");
        assertEquals(outputLength, okm.length, "HKDF output length should match request");
    }
}

