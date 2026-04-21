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
 * FIPS mode tests for OpenSSL PBKDF2 operations.
 * Tests the same functionality as TestOpenSSLPBKDF2Native but using FIPS adapter.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLPBKDF2FIPS {

    private static NativeOpenSSLAdapterFIPS fipsAdapter;
    private static boolean fipsAvailable = false;

    private static final byte[] TEST_PASSWORD = "test-password-fips".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_SALT = "test-salt-fips".getBytes(StandardCharsets.UTF_8);
    private static final int TEST_ITERATIONS = 1000;

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
    public void testPbkdf2Sha256() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 32;
        byte[] derived = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        
        assertNotNull(derived, "PBKDF2 result should not be null");
        assertEquals(keyLength, derived.length, "PBKDF2 output length should match request");
    }

    @Test
    public void testPbkdf2Sha1() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 20;
        byte[] derived = fipsAdapter.PBKDF2_derive("SHA1", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        
        assertNotNull(derived, "PBKDF2 result should not be null");
        assertEquals(keyLength, derived.length, "PBKDF2 output length should match request");
    }

    @Test
    public void testPbkdf2Sha512() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 64;
        byte[] derived = fipsAdapter.PBKDF2_derive("SHA512", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        
        assertNotNull(derived, "PBKDF2 result should not be null");
        assertEquals(keyLength, derived.length, "PBKDF2 output length should match request");
    }

    @Test
    public void testPbkdf2Consistency() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 32;
        byte[] derived1 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        byte[] derived2 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        
        assertArrayEquals(derived1, derived2, "PBKDF2 should be consistent for same inputs");
    }

    @Test
    public void testPbkdf2DifferentIterations() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 32;
        byte[] derived1 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, 1000, keyLength);
        byte[] derived2 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, 2000, keyLength);
        
        assertFalse(java.util.Arrays.equals(derived1, derived2), 
                "PBKDF2 should differ for different iteration counts");
    }

    @Test
    public void testPbkdf2DifferentSalts() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] salt2 = "different-salt-fips".getBytes(StandardCharsets.UTF_8);
        int keyLength = 32;
        
        byte[] derived1 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        byte[] derived2 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, salt2, TEST_ITERATIONS, keyLength);
        
        assertFalse(java.util.Arrays.equals(derived1, derived2), 
                "PBKDF2 should differ for different salts");
    }

    @Test
    public void testPbkdf2VariousKeyLengths() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int[] keyLengths = {16, 24, 32, 48, 64};
        
        for (int keyLength : keyLengths) {
            byte[] derived = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
            assertNotNull(derived, "PBKDF2 result should not be null for length " + keyLength);
            assertEquals(keyLength, derived.length, "PBKDF2 output length should match request");
        }
    }

    @Test
    public void testPbkdf2MinimalIterations() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 32;
        byte[] derived = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, 1, keyLength);
        
        assertNotNull(derived, "PBKDF2 should work with minimal iterations");
        assertEquals(keyLength, derived.length, "PBKDF2 output length should match request");
    }
}

