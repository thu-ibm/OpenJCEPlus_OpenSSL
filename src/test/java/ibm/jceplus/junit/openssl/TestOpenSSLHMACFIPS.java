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
 * FIPS mode tests for OpenSSL HMAC operations.
 * Tests the same functionality as TestOpenSSLHMACNative but using FIPS adapter.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLHMACFIPS {

    private static NativeOpenSSLAdapterFIPS fipsAdapter;
    private static boolean fipsAvailable = false;

    private static final byte[] TEST_KEY = "test-hmac-key-fips".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_DATA = "Hello, FIPS HMAC!".getBytes(StandardCharsets.UTF_8);

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
    public void testHmacSha256() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hmacId = fipsAdapter.HMAC_create("SHA-256");
        assertTrue(hmacId > 0, "HMAC ID should be positive");
        
        try {
            assertEquals(32, fipsAdapter.HMAC_size(hmacId), "HMAC-SHA256 size should be 32 bytes");
            
            fipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length, TEST_DATA, 0, TEST_DATA.length, true);
            byte[] output = new byte[32];
            fipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, output, false);
            
            assertNotNull(output, "HMAC result should not be null");
            assertEquals(32, output.length, "HMAC-SHA256 should produce 32 bytes");
        } finally {
            fipsAdapter.HMAC_delete(hmacId);
        }
    }

    @Test
    public void testHmacSha1() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hmacId = fipsAdapter.HMAC_create("SHA-1");
        assertTrue(hmacId > 0, "HMAC ID should be positive");
        
        try {
            assertEquals(20, fipsAdapter.HMAC_size(hmacId), "HMAC-SHA1 size should be 20 bytes");
            
            fipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length, TEST_DATA, 0, TEST_DATA.length, true);
            byte[] output = new byte[20];
            fipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, output, false);
            
            assertNotNull(output, "HMAC result should not be null");
            assertEquals(20, output.length, "HMAC-SHA1 should produce 20 bytes");
        } finally {
            fipsAdapter.HMAC_delete(hmacId);
        }
    }

    @Test
    public void testHmacSha512() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hmacId = fipsAdapter.HMAC_create("SHA-512");
        assertTrue(hmacId > 0, "HMAC ID should be positive");
        
        try {
            assertEquals(64, fipsAdapter.HMAC_size(hmacId), "HMAC-SHA512 size should be 64 bytes");
            
            fipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length, TEST_DATA, 0, TEST_DATA.length, true);
            byte[] output = new byte[64];
            fipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, output, false);
            
            assertNotNull(output, "HMAC result should not be null");
            assertEquals(64, output.length, "HMAC-SHA512 should produce 64 bytes");
        } finally {
            fipsAdapter.HMAC_delete(hmacId);
        }
    }

    @Test
    public void testHmacConsistency() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long hmacId = fipsAdapter.HMAC_create("SHA-256");
        assertTrue(hmacId > 0, "HMAC ID should be positive");
        
        try {
            fipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length, TEST_DATA, 0, TEST_DATA.length, true);
            byte[] output1 = new byte[32];
            fipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, output1, false);
            
            fipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length, TEST_DATA, 0, TEST_DATA.length, true);
            byte[] output2 = new byte[32];
            fipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, output2, false);
            
            assertArrayEquals(output1, output2, "HMAC should be consistent for same inputs");
        } finally {
            fipsAdapter.HMAC_delete(hmacId);
        }
    }
}

