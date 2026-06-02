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
public class TestOpenSSLPBKDF2Native {

    private static NativeOpenSSLAdapterNonFIPS nonFipsAdapter;

    private static final byte[] PASSWORD =
            "password".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT =
            "salt".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public void setUp() {
        try {
            nonFipsAdapter = NativeOpenSSLAdapterNonFIPS.getInstance();
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL adapter: " + e.getMessage());
        }
    }

    @Test
    public void testPbkdf2DeriveLifecycle() throws Exception {
        byte[] derived = nonFipsAdapter.PBKDF2_derive("SHA256", PASSWORD, SALT, 4096, 32);
        assertNotNull(derived, "PBKDF2 output should not be null");
        assertEquals(32, derived.length, "PBKDF2 output length should match request");
    }

    @Test
    public void testPbkdf2DeterministicForSameInputs() throws Exception {
        byte[] derived1 = nonFipsAdapter.PBKDF2_derive("SHA256", PASSWORD, SALT, 4096, 32);
        byte[] derived2 = nonFipsAdapter.PBKDF2_derive("SHA256", PASSWORD, SALT, 4096, 32);

        assertArrayEquals(derived1, derived2,
                "PBKDF2 should be deterministic for same inputs");
    }

    @Test
    public void testPbkdf2InputVariationsChangeOutput() throws Exception {
        byte[] base = nonFipsAdapter.PBKDF2_derive("SHA256", PASSWORD, SALT, 4096, 32);
        byte[] differentSalt = nonFipsAdapter.PBKDF2_derive("SHA256", PASSWORD,
                "different-salt".getBytes(StandardCharsets.UTF_8), 4096, 32);
        byte[] differentIterations = nonFipsAdapter.PBKDF2_derive("SHA256", PASSWORD, SALT, 8192, 32);

        assertFalse(Arrays.equals(base, differentSalt),
                "Changing the salt should change the PBKDF2 output");
        assertFalse(Arrays.equals(base, differentIterations),
                "Changing the iteration count should change the PBKDF2 output");
    }

    @Test
    public void testPbkdf2MultipleAlgorithms() throws Exception {
        byte[] derived256 = nonFipsAdapter.PBKDF2_derive("SHA256", PASSWORD, SALT, 4096, 32);
        byte[] derived512 = nonFipsAdapter.PBKDF2_derive("SHA512", PASSWORD, SALT, 4096, 32);

        assertNotNull(derived256, "PBKDF2 SHA-256 output should not be null");
        assertNotNull(derived512, "PBKDF2 SHA-512 output should not be null");
        assertEquals(32, derived256.length, "PBKDF2 SHA-256 output length should match request");
        assertEquals(32, derived512.length, "PBKDF2 SHA-512 output length should match request");
        assertFalse(Arrays.equals(derived256, derived512),
                "Different PBKDF2 digest algorithms should not produce the same output");
    }
}

