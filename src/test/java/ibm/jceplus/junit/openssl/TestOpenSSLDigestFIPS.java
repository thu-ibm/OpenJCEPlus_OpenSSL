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
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * FIPS mode tests for OpenSSL Digest operations.
 * Tests the same functionality as TestOpenSSLDigestNative but using FIPS adapter.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLDigestFIPS {

    private static NativeOpenSSLAdapterFIPS fipsAdapter;
    private static boolean fipsAvailable = false;

    private static final byte[] TEST_INPUT =
            "Hello, OpenSSL FIPS native interface!".getBytes(StandardCharsets.UTF_8);

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
    public void testDigestLifecycle() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long digestId = fipsAdapter.DIGEST_create("SHA-256");
        assertTrue(digestId > 0, "Digest ID should be positive");

        try {
            assertEquals(32, fipsAdapter.DIGEST_size(digestId),
                    "SHA-256 digest size should be 32 bytes");

            assertEquals(1,
                    fipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length),
                    "Digest update should report success");

            long digestCopyId = fipsAdapter.DIGEST_copy(digestId);
            assertTrue(digestCopyId > 0, "Digest copy ID should be positive");
            try {
                byte[] copiedDigest = fipsAdapter.DIGEST_digest(digestCopyId);
                assertNotNull(copiedDigest, "Copied digest result should not be null");
                assertEquals(32, copiedDigest.length, "Copied digest length should be 32 bytes");
            } finally {
                fipsAdapter.DIGEST_delete(digestCopyId);
            }

            byte[] output = new byte[32];
            int written = fipsAdapter.DIGEST_digest_and_reset(digestId, output);
            assertEquals(1, written, "Digest-and-reset should report success");

            fipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length);
            byte[] digestAfterReset = fipsAdapter.DIGEST_digest(digestId);

            assertArrayEquals(output, digestAfterReset,
                    "Digest result after reset/recompute should match prior output");

            fipsAdapter.DIGEST_reset(digestId);
            byte[] emptyDigest = fipsAdapter.DIGEST_digest(digestId);
            assertNotNull(emptyDigest, "Empty digest result should not be null");
            assertEquals(32, emptyDigest.length, "Empty digest length should be 32 bytes");
            assertFalse(Arrays.equals(output, emptyDigest),
                    "Digest of input should differ from digest of empty input");
        } finally {
            fipsAdapter.DIGEST_delete(digestId);
        }
    }

    @Test
    public void testDigestZeroLengthUpdateAndResetReuse() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        long digestId = fipsAdapter.DIGEST_create("SHA-256");
        assertTrue(digestId > 0, "Digest ID should be positive");

        try {
            assertEquals(1, fipsAdapter.DIGEST_update(digestId, new byte[0], 0, 0),
                    "Zero-length digest update should report success");

            byte[] emptyDigestFromUpdate = fipsAdapter.DIGEST_digest(digestId);
            assertNotNull(emptyDigestFromUpdate, "Digest result should not be null");
            assertEquals(32, emptyDigestFromUpdate.length, "SHA-256 digest length should be 32 bytes");

            fipsAdapter.DIGEST_reset(digestId);
            assertEquals(1, fipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length),
                    "Digest update after reset should report success");

            byte[] digestAfterReset = fipsAdapter.DIGEST_digest(digestId);
            assertNotNull(digestAfterReset, "Digest after reset should not be null");
            assertEquals(32, digestAfterReset.length, "SHA-256 digest length should be 32 bytes");
            assertFalse(Arrays.equals(emptyDigestFromUpdate, digestAfterReset),
                    "Digest of empty input should differ from digest of test input");
        } finally {
            fipsAdapter.DIGEST_delete(digestId);
        }
    }

    @Test
    public void testMultipleDigestAlgorithms() throws Exception {
        assumeTrue(fipsAvailable, "FIPS mode not available");
        
        String[] algorithms = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"};
        int[] expectedSizes = {20, 28, 32, 48, 64};

        for (int i = 0; i < algorithms.length; i++) {
            long digestId = fipsAdapter.DIGEST_create(algorithms[i]);
            assertTrue(digestId > 0, algorithms[i] + " digest ID should be positive");

            try {
                assertEquals(expectedSizes[i], fipsAdapter.DIGEST_size(digestId),
                        algorithms[i] + " digest size should be " + expectedSizes[i]);

                fipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length);
                byte[] digest = fipsAdapter.DIGEST_digest(digestId);
                assertNotNull(digest, algorithms[i] + " digest result should not be null");
                assertEquals(expectedSizes[i], digest.length,
                        algorithms[i] + " digest length should be " + expectedSizes[i]);
            } finally {
                fipsAdapter.DIGEST_delete(digestId);
            }
        }
    }
}


