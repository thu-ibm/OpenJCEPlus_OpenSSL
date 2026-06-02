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
public class TestOpenSSLDigestNative {

    private static NativeOpenSSLAdapterNonFIPS nonFipsAdapter;

    private static final byte[] TEST_INPUT =
            "Hello, OpenSSL native interface!".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public void setUp() {
        try {
            nonFipsAdapter = NativeOpenSSLAdapterNonFIPS.getInstance();
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL adapter: " + e.getMessage());
        }
    }

    @Test
    public void testDigestLifecycle() throws Exception {
        long digestId = nonFipsAdapter.DIGEST_create("SHA-256");
        assertTrue(digestId > 0, "Digest ID should be positive");

        try {
            assertEquals(32, nonFipsAdapter.DIGEST_size(digestId),
                    "SHA-256 digest size should be 32 bytes");

            assertEquals(1,
                    nonFipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length),
                    "Digest update should report success");

            long digestCopyId = nonFipsAdapter.DIGEST_copy(digestId);
            assertTrue(digestCopyId > 0, "Digest copy ID should be positive");
            try {
                byte[] copiedDigest = nonFipsAdapter.DIGEST_digest(digestCopyId);
                assertNotNull(copiedDigest, "Copied digest result should not be null");
                assertEquals(32, copiedDigest.length, "Copied digest length should be 32 bytes");
            } finally {
                nonFipsAdapter.DIGEST_delete(digestCopyId);
            }

            byte[] output = new byte[32];
            int written = nonFipsAdapter.DIGEST_digest_and_reset(digestId, output);
            assertEquals(1, written, "Digest-and-reset should report success");

            nonFipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length);
            byte[] digestAfterReset = nonFipsAdapter.DIGEST_digest(digestId);

            assertArrayEquals(output, digestAfterReset,
                    "Digest result after reset/recompute should match prior output");

            nonFipsAdapter.DIGEST_reset(digestId);
            byte[] emptyDigest = nonFipsAdapter.DIGEST_digest(digestId);
            assertNotNull(emptyDigest, "Empty digest result should not be null");
            assertEquals(32, emptyDigest.length, "Empty digest length should be 32 bytes");
            assertFalse(Arrays.equals(output, emptyDigest),
                    "Digest of input should differ from digest of empty input");
        } finally {
            nonFipsAdapter.DIGEST_delete(digestId);
        }
    }

    @Test
    public void testDigestZeroLengthUpdateAndResetReuse() throws Exception {
        long digestId = nonFipsAdapter.DIGEST_create("SHA-256");
        assertTrue(digestId > 0, "Digest ID should be positive");

        try {
            assertEquals(1, nonFipsAdapter.DIGEST_update(digestId, new byte[0], 0, 0),
                    "Zero-length digest update should report success");

            byte[] emptyDigestFromUpdate = nonFipsAdapter.DIGEST_digest(digestId);
            assertNotNull(emptyDigestFromUpdate, "Digest result should not be null");
            assertEquals(32, emptyDigestFromUpdate.length, "SHA-256 digest length should be 32 bytes");

            nonFipsAdapter.DIGEST_reset(digestId);
            assertEquals(1, nonFipsAdapter.DIGEST_update(digestId, TEST_INPUT, 0, TEST_INPUT.length),
                    "Digest update after reset should report success");

            byte[] digestAfterReset = nonFipsAdapter.DIGEST_digest(digestId);
            assertNotNull(digestAfterReset, "Digest after reset should not be null");
            assertEquals(32, digestAfterReset.length, "Digest after reset should be 32 bytes");
            assertFalse(Arrays.equals(emptyDigestFromUpdate, digestAfterReset),
                    "Digest of empty input should differ from digest of TEST_INPUT");
        } finally {
            nonFipsAdapter.DIGEST_delete(digestId);
        }
    }

    @Test
    public void testDigestOffsetUpdateAndCopyIndependence() throws Exception {
        byte[] prefixedInput = "prefix-Hello, OpenSSL native interface!-suffix"
                .getBytes(StandardCharsets.UTF_8);
        int offset = "prefix-".getBytes(StandardCharsets.UTF_8).length;
        int len = TEST_INPUT.length;

        long digestId = nonFipsAdapter.DIGEST_create("SHA-256");
        assertTrue(digestId > 0, "Digest ID should be positive");

        try {
            assertEquals(1, nonFipsAdapter.DIGEST_update(digestId, prefixedInput, offset, len),
                    "Offset digest update should report success");

            long digestCopyId = nonFipsAdapter.DIGEST_copy(digestId);
            assertTrue(digestCopyId > 0, "Digest copy ID should be positive");
            try {
                assertEquals(1, nonFipsAdapter.DIGEST_update(digestId,
                        "A".getBytes(StandardCharsets.UTF_8), 0, 1),
                        "Original digest should accept additional update");
                assertEquals(1, nonFipsAdapter.DIGEST_update(digestCopyId,
                        "B".getBytes(StandardCharsets.UTF_8), 0, 1),
                        "Copied digest should accept independent update");

                byte[] digestOriginal = nonFipsAdapter.DIGEST_digest(digestId);
                byte[] digestCopy = nonFipsAdapter.DIGEST_digest(digestCopyId);

                assertNotNull(digestOriginal, "Original digest result should not be null");
                assertNotNull(digestCopy, "Copied digest result should not be null");
                assertFalse(Arrays.equals(digestOriginal, digestCopy),
                        "Original and copied digest results should diverge after independent updates");
            } finally {
                nonFipsAdapter.DIGEST_delete(digestCopyId);
            }
        } finally {
            nonFipsAdapter.DIGEST_delete(digestId);
        }
    }

    // TODO: Re-enable when SHA3 support is available in OpenSSL installation
    // Currently fails with error code 17 - SHA3-256 algorithm not available
    /*
    @Test
    public void testDigestMultipleAlgorithms() throws Exception {
        long sha512Id = nonFipsAdapter.DIGEST_create("SHA-512");
        long sha3Id = nonFipsAdapter.DIGEST_create("SHA3-256");
        assertTrue(sha512Id > 0, "SHA-512 digest ID should be positive");
        assertTrue(sha3Id > 0, "SHA3-256 digest ID should be positive");

        try {
            assertEquals(64, nonFipsAdapter.DIGEST_size(sha512Id),
                    "SHA-512 digest size should be 64 bytes");
            assertEquals(32, nonFipsAdapter.DIGEST_size(sha3Id),
                    "SHA3-256 digest size should be 32 bytes");

            assertEquals(1, nonFipsAdapter.DIGEST_update(sha512Id, TEST_INPUT, 0, TEST_INPUT.length),
                    "SHA-512 update should report success");
            assertEquals(1, nonFipsAdapter.DIGEST_update(sha3Id, TEST_INPUT, 0, TEST_INPUT.length),
                    "SHA3-256 update should report success");

            byte[] sha512Digest = nonFipsAdapter.DIGEST_digest(sha512Id);
            byte[] sha3Digest = nonFipsAdapter.DIGEST_digest(sha3Id);

            assertEquals(64, sha512Digest.length, "SHA-512 digest output length should be 64 bytes");
            assertEquals(32, sha3Digest.length, "SHA3-256 digest output length should be 32 bytes");
            assertFalse(Arrays.equals(Arrays.copyOf(sha512Digest, 32), sha3Digest),
                    "Different digest algorithms should not produce the same output");
        } finally {
            nonFipsAdapter.DIGEST_delete(sha512Id);
            nonFipsAdapter.DIGEST_delete(sha3Id);
        }
    }
    */
}

