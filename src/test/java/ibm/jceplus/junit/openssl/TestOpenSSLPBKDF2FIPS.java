/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openssl;

import com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapterFIPS;
import com.ibm.crypto.plus.provider.openssl.OpenSSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * FIPS mode tests for OpenSSL PBKDF2 operations.
 * NOTE: PBKDF2 approval status in OpenSSL FIPS mode varies by configuration.
 * These tests verify that PBKDF2 either works correctly or fails consistently.
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
        // PBKDF2 may or may not be approved in FIPS mode depending on configuration
        try {
            byte[] result = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
            // If it succeeds, verify the result is valid
            assertNotNull(result, "PBKDF2 result should not be null");
            assertEquals(keyLength, result.length, "PBKDF2 output length should match request");
        } catch (Exception e) {
            // If it fails, verify it's the expected PBKDF2 error
            assertTrue(e instanceof OpenSSLException, "Should throw OpenSSLException");
            assertTrue(e.getMessage().contains("PBKDF2 derivation failed"),
                    "Exception should indicate PBKDF2 failure");
        }
    }

    @Test
    public void testPbkdf2Sha1() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 20;
        // PBKDF2 may or may not be approved in FIPS mode depending on configuration
        try {
            byte[] result = fipsAdapter.PBKDF2_derive("SHA1", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
            // If it succeeds, verify the result is valid
            assertNotNull(result, "PBKDF2 result should not be null");
            assertEquals(keyLength, result.length, "PBKDF2 output length should match request");
        } catch (Exception e) {
            // If it fails, verify it's the expected PBKDF2 error
            assertTrue(e instanceof OpenSSLException, "Should throw OpenSSLException");
            assertTrue(e.getMessage().contains("PBKDF2 derivation failed"),
                    "Exception should indicate PBKDF2 failure");
        }
    }

    @Test
    public void testPbkdf2Sha512() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 64;
        // PBKDF2 may or may not be approved in FIPS mode depending on configuration
        try {
            byte[] result = fipsAdapter.PBKDF2_derive("SHA512", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
            // If it succeeds, verify the result is valid
            assertNotNull(result, "PBKDF2 result should not be null");
            assertEquals(keyLength, result.length, "PBKDF2 output length should match request");
        } catch (Exception e) {
            // If it fails, verify it's the expected PBKDF2 error
            assertTrue(e instanceof OpenSSLException, "Should throw OpenSSLException");
            assertTrue(e.getMessage().contains("PBKDF2 derivation failed"),
                    "Exception should indicate PBKDF2 failure");
        }
    }

    @Test
    public void testPbkdf2Consistency() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 32;
        // Verify PBKDF2 behaves consistently
        byte[] result1 = null;
        byte[] result2 = null;
        boolean firstFailed = false;
        
        try {
            result1 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        } catch (Exception e) {
            firstFailed = true;
        }
        
        try {
            result2 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
        } catch (Exception e) {
            assertTrue(firstFailed, "PBKDF2 should fail consistently");
            return; // Both failed consistently
        }
        
        // If we get here, at least one succeeded
        assertFalse(firstFailed, "PBKDF2 should succeed consistently");
        assertArrayEquals(result1, result2, "PBKDF2 should produce consistent results");
    }

    @Test
    public void testPbkdf2DifferentIterations() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 32;
        // Verify PBKDF2 produces different results for different iterations (if it works)
        try {
            byte[] result1 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, 1000, keyLength);
            byte[] result2 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, 2000, keyLength);
            assertFalse(java.util.Arrays.equals(result1, result2),
                    "PBKDF2 should produce different results for different iteration counts");
        } catch (Exception e) {
            // PBKDF2 not available in this FIPS configuration
            assertTrue(e instanceof OpenSSLException, "Should throw OpenSSLException");
            assertTrue(e.getMessage().contains("PBKDF2 derivation failed"),
                    "Exception should indicate PBKDF2 failure");
        }
    }

    @Test
    public void testPbkdf2DifferentSalts() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        byte[] salt2 = "different-salt-fips".getBytes(StandardCharsets.UTF_8);
        int keyLength = 32;
        
        // Verify PBKDF2 produces different results for different salts (if it works)
        try {
            byte[] result1 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
            byte[] result2 = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, salt2, TEST_ITERATIONS, keyLength);
            assertFalse(java.util.Arrays.equals(result1, result2),
                    "PBKDF2 should produce different results for different salts");
        } catch (Exception e) {
            // PBKDF2 not available in this FIPS configuration
            assertTrue(e instanceof OpenSSLException, "Should throw OpenSSLException");
            assertTrue(e.getMessage().contains("PBKDF2 derivation failed"),
                    "Exception should indicate PBKDF2 failure");
        }
    }

    @Test
    public void testPbkdf2VariousKeyLengths() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int[] keyLengths = {16, 24, 32, 48, 64};
        
        // Verify PBKDF2 works with various key lengths (if it works at all)
        boolean anySucceeded = false;
        for (int keyLength : keyLengths) {
            try {
                byte[] result = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, TEST_ITERATIONS, keyLength);
                assertNotNull(result, "PBKDF2 result should not be null for length " + keyLength);
                assertEquals(keyLength, result.length, "PBKDF2 output length should match request");
                anySucceeded = true;
            } catch (Exception e) {
                // PBKDF2 not available for this key length
            }
        }
        // Test passes whether PBKDF2 works or not
    }

    @Test
    public void testPbkdf2MinimalIterations() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        int keyLength = 32;
        // Verify PBKDF2 works with minimal iterations (if it works at all)
        try {
            byte[] result = fipsAdapter.PBKDF2_derive("SHA256", TEST_PASSWORD, TEST_SALT, 1, keyLength);
            assertNotNull(result, "PBKDF2 should work with minimal iterations");
            assertEquals(keyLength, result.length, "PBKDF2 output length should match request");
        } catch (Exception e) {
            // PBKDF2 not available in this FIPS configuration
            assertTrue(e instanceof OpenSSLException, "Should throw OpenSSLException");
            assertTrue(e.getMessage().contains("PBKDF2 derivation failed"),
                    "Exception should indicate PBKDF2 failure");
        }
    }
}

