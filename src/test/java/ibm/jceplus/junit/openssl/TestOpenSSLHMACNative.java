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
public class TestOpenSSLHMACNative {

    private static NativeOpenSSLAdapterNonFIPS nonFipsAdapter;

    private static final byte[] TEST_INPUT =
            "Hello, OpenSSL native interface!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_KEY =
            "hmac-key-material".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public void setUp() {
        try {
            nonFipsAdapter = NativeOpenSSLAdapterNonFIPS.getInstance();
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL adapter: " + e.getMessage());
        }
    }

    @Test
    public void testHmacLifecycle() throws Exception {
        long hmacId = nonFipsAdapter.HMAC_create("SHA-256");
        assertTrue(hmacId > 0, "HMAC ID should be positive");

        try {
            assertEquals(32, nonFipsAdapter.HMAC_size(hmacId),
                    "HMAC-SHA256 size should be 32 bytes");

            int updated = nonFipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length, TEST_INPUT, 0,
                    TEST_INPUT.length, true);
            assertEquals(1, updated, "HMAC update should report success");

            byte[] output = new byte[32];
            int written = nonFipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, output, false);
            assertEquals(1, written, "HMAC final should report success");

            byte[] secondOutput = new byte[32];
            int secondUpdated = nonFipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length, TEST_INPUT, 0,
                    TEST_INPUT.length, true);
            assertEquals(1, secondUpdated, "Second HMAC update should report success");
            int secondWritten = nonFipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, secondOutput, false);
            assertEquals(1, secondWritten, "Second HMAC final should report success");

            assertArrayEquals(output, secondOutput,
                    "HMAC should be deterministic for same key and input");
        } finally {
            nonFipsAdapter.HMAC_delete(hmacId);
        }
    }

    @Test
    public void testHmacZeroLengthUpdateAndReinit() throws Exception {
        long hmacId = nonFipsAdapter.HMAC_create("SHA-256");
        assertTrue(hmacId > 0, "HMAC ID should be positive");

        try {
            assertEquals(1, nonFipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length,
                    new byte[0], 0, 0, true),
                    "Zero-length HMAC update should report success");

            byte[] emptyMac = new byte[32];
            assertEquals(1, nonFipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, emptyMac, false),
                    "Final after zero-length update should report success");

            assertEquals(1, nonFipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length,
                    TEST_INPUT, 0, TEST_INPUT.length, true),
                    "HMAC update after reuse should report success");

            byte[] messageMac = new byte[32];
            assertEquals(1, nonFipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, messageMac, false),
                    "Final after reuse should report success");

            assertFalse(Arrays.equals(emptyMac, messageMac),
                    "HMAC of empty input should differ from HMAC of TEST_INPUT");
        } finally {
            nonFipsAdapter.HMAC_delete(hmacId);
        }
    }

    @Test
    public void testHmacOffsetUpdateAndDeterminism() throws Exception {
        byte[] prefixedInput = "prefix-Hello, OpenSSL native interface!-suffix"
                .getBytes(StandardCharsets.UTF_8);
        int offset = "prefix-".getBytes(StandardCharsets.UTF_8).length;
        int len = TEST_INPUT.length;

        long hmacId = nonFipsAdapter.HMAC_create("SHA-256");
        assertTrue(hmacId > 0, "HMAC ID should be positive");

        try {
            assertEquals(1, nonFipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length,
                    prefixedInput, offset, len, true),
                    "Offset HMAC update should report success");

            byte[] offsetMac = new byte[32];
            assertEquals(1, nonFipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, offsetMac, false),
                    "Offset final should report success");

            assertEquals(1, nonFipsAdapter.HMAC_update(hmacId, TEST_KEY, TEST_KEY.length,
                    TEST_INPUT, 0, TEST_INPUT.length, true),
                    "Direct HMAC update should report success");

            byte[] directMac = new byte[32];
            assertEquals(1, nonFipsAdapter.HMAC_doFinal(hmacId, TEST_KEY, TEST_KEY.length, directMac, false),
                    "Direct final should report success");

            assertArrayEquals(directMac, offsetMac,
                    "Offset and direct HMAC results should match for same logical input");
        } finally {
            nonFipsAdapter.HMAC_delete(hmacId);
        }
    }

    @Test
    public void testHmacMultipleAlgorithms() throws Exception {
        long sha256Id = nonFipsAdapter.HMAC_create("SHA-256");
        assertTrue(sha256Id > 0, "SHA-256 HMAC ID should be positive");

        // Try SHA3-256, but it may not be available in all OpenSSL configurations
        long sha3Id = 0;
        boolean sha3Available = false;
        try {
            sha3Id = nonFipsAdapter.HMAC_create("SHA3-256");
            sha3Available = (sha3Id > 0);
        } catch (Exception e) {
            // SHA3-256 not available in this OpenSSL configuration
            System.out.println("SHA3-256 not available, skipping: " + e.getMessage());
        }

        try {
            assertEquals(32, nonFipsAdapter.HMAC_size(sha256Id),
                    "SHA-256 HMAC size should be 32 bytes");
            
            if (sha3Available) {
                assertEquals(32, nonFipsAdapter.HMAC_size(sha3Id),
                        "SHA3-256 HMAC size should be 32 bytes");
            }

            assertEquals(1, nonFipsAdapter.HMAC_update(sha256Id, TEST_KEY, TEST_KEY.length,
                    TEST_INPUT, 0, TEST_INPUT.length, true),
                    "SHA-256 HMAC update should report success");
            if (sha3Available) {
                assertEquals(1, nonFipsAdapter.HMAC_update(sha3Id, TEST_KEY, TEST_KEY.length,
                        TEST_INPUT, 0, TEST_INPUT.length, true),
                        "SHA3-256 HMAC update should report success");
            }

            byte[] sha256Mac = new byte[32];
            assertEquals(1, nonFipsAdapter.HMAC_doFinal(sha256Id, TEST_KEY, TEST_KEY.length, sha256Mac, false),
                    "SHA-256 HMAC final should report success");
            
            if (sha3Available) {
                byte[] sha3Mac = new byte[32];
                assertEquals(1, nonFipsAdapter.HMAC_doFinal(sha3Id, TEST_KEY, TEST_KEY.length, sha3Mac, false),
                        "SHA3-256 HMAC final should report success");
                assertFalse(Arrays.equals(sha256Mac, sha3Mac),
                        "Different HMAC algorithms should not produce the same output");
            }
        } finally {
            nonFipsAdapter.HMAC_delete(sha256Id);
            if (sha3Available && sha3Id > 0) {
                nonFipsAdapter.HMAC_delete(sha3Id);
            }
        }
    }
}

