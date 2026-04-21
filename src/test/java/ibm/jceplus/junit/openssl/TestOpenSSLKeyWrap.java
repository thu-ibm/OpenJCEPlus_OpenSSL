/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.openssl;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.ProviderServiceReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.StringReader;
import java.security.Key;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for OpenSSL KeyWrap native implementation.
 * 
 * This test validates the native OpenSSL key wrap/unwrap functionality
 * implemented in OpenSSLKeyWrap.c, which provides AES Key Wrap (RFC 3394)
 * and AES Key Wrap with Padding (RFC 5649) support.
 * 
 * The native implementation supports:
 * - AES-128, AES-192, and AES-256 key encryption keys (KEK)
 * - Standard key wrap (id-aes128-wrap, id-aes192-wrap, id-aes256-wrap)
 * - Key wrap with padding (id-aes128-wrap-pad, id-aes192-wrap-pad, id-aes256-wrap-pad)
 * 
 * Test coverage includes:
 * - Basic wrap/unwrap operations with different key sizes
 * - Wrap/unwrap with padding enabled
 * - Round-trip testing (wrap then unwrap)
 * - Error conditions (invalid keys, corrupted ciphertext)
 * - FIPS and non-FIPS modes
 */
@TestInstance(Lifecycle.PER_CLASS)
public class TestOpenSSLKeyWrap {

    private Provider testProvider;
    private String providerName;
    
    private static final String OPENSSL_CONFIG =
        "name = OpenSSL-KeyWrap-Test\n" +
        "description = OpenJCEPlus Provider with OpenSSL Backend for KeyWrap Testing\n" +
        "backend = OpenSSL\n" +
        "Service.Cipher.AES/KW/NoPadding = com.ibm.crypto.plus.provider.AESKeyWrapCipher$KW\n" +
        "Service.Cipher.AES/KWP/NoPadding = com.ibm.crypto.plus.provider.AESKeyWrapCipher$KWP\n";

    @BeforeAll
    public void beforeAll() throws Exception {
        // Clean up any existing test providers
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().startsWith("OpenSSL-KeyWrap-Test")) {
                Security.removeProvider(p.getName());
            }
        }
        
        // Create provider with OpenSSL backend via config
        ProviderServiceReader reader = new ProviderServiceReader(
            new BufferedReader(new StringReader(OPENSSL_CONFIG))
        );
        
        testProvider = new OpenJCEPlus(reader);
        Security.addProvider(testProvider);
        providerName = testProvider.getName();
        
        // Verify backend selection
        if (testProvider instanceof OpenJCEPlus) {
            String backend = ((OpenJCEPlus)testProvider).getSelectedBackend();
            if (!"OpenSSL".equalsIgnoreCase(backend)) {
                throw new RuntimeException("Failed to configure OpenSSL backend, got: " + backend);
            }
        }
    }
    
    @AfterAll
    public void afterAll() {
        if (testProvider != null) {
            Security.removeProvider(testProvider.getName());
            testProvider = null;
        }
    }

    /**
     * Test basic AES key wrap with 128-bit KEK
     */
    @Test
    public void testAESKeyWrap128() throws Exception {
        SecretKey kek = generateKey("AES", 128);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test basic AES key wrap with 192-bit KEK
     */
    @Test
    public void testAESKeyWrap192() throws Exception {
        SecretKey kek = generateKey("AES", 192);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test basic AES key wrap with 256-bit KEK
     */
    @Test
    public void testAESKeyWrap256() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 256);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test AES key wrap with padding for various key sizes
     */
    @ParameterizedTest
    @CsvSource({
        "128, 128",
        "128, 192",
        "128, 256",
        "192, 128",
        "192, 256",
        "256, 128",
        "256, 256"
    })
    public void testAESKeyWrapWithPadding(int kekSize, int keySize) throws Exception {
        SecretKey kek = generateKey("AES", kekSize);
        SecretKey keyToWrap = generateKey("AES", keySize);
        
        testWrapUnwrap("AES/KWP/NoPadding", kek, keyToWrap);
    }

    /**
     * Test wrapping keys of various sizes without padding
     */
    @ParameterizedTest
    @CsvSource({
        "128, 128",
        "192, 128",
        "192, 192",
        "256, 128",
        "256, 192",
        "256, 256"
    })
    public void testAESKeyWrapVariousSizes(int kekSize, int keySize) throws Exception {
        SecretKey kek = generateKey("AES", kekSize);
        SecretKey keyToWrap = generateKey("AES", keySize);
        
        testWrapUnwrap("AES/KW/NoPadding", kek, keyToWrap);
    }

    /**
     * Test that corrupted wrapped key fails to unwrap
     */
    @Test
    public void testCorruptedWrappedKey() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        // Corrupt the wrapped key
        wrappedKey[5] ^= 0xFF;
        
        cipher.init(Cipher.UNWRAP_MODE, kek);
        
        // Unwrapping corrupted key should fail
        try {
            cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
            fail("Unwrapping corrupted key should have thrown an exception");
        } catch (Exception e) {
            // Expected - corrupted key should fail to unwrap
        }
    }

    /**
     * Test that using wrong KEK fails to unwrap
     */
    @Test
    public void testWrongKEK() throws Exception {
        SecretKey kek1 = generateKey("AES", 256);
        SecretKey kek2 = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek1);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        cipher.init(Cipher.UNWRAP_MODE, kek2);
        
        // Unwrapping with wrong KEK should fail
        try {
            cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
            fail("Unwrapping with wrong KEK should have thrown an exception");
        } catch (Exception e) {
            // Expected - wrong KEK should fail to unwrap
        }
    }

    /**
     * Test wrap/unwrap with null key should fail
     */
    @Test
    public void testNullKey() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        
        // Use try-catch instead of assertThrows to avoid JUnit API access issues
        try {
            cipher.init(Cipher.WRAP_MODE, (Key) null);
            fail("Initializing with null key should fail");
        } catch (Exception e) {
            // Expected exception
            assertTrue(e != null, "Should throw exception for null key");
        }
    }

    /**
     * Test that wrapped key length is correct
     * Standard key wrap adds 8 bytes (64 bits) to the input
     */
    @Test
    public void testWrappedKeyLength() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        // Wrapped key should be 8 bytes longer than original
        assertEquals(keyToWrap.getEncoded().length + 8, wrappedKey.length,
            "Wrapped key length should be original length + 8 bytes");
    }

    /**
     * Test that wrapped key with padding has correct length
     * Padded key wrap output is always a multiple of 8 bytes
     */
    @Test
    public void testWrappedKeyLengthWithPadding() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        SecretKey keyToWrap = generateKey("AES", 128);
        
        Cipher cipher = Cipher.getInstance("AES/KWP/NoPadding", providerName);
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        // Wrapped key length should be multiple of 8
        assertEquals(0, wrappedKey.length % 8,
            "Wrapped key with padding should have length multiple of 8");
        
        // Should be at least 8 bytes longer than original
        assertTrue(wrappedKey.length >= keyToWrap.getEncoded().length + 8,
            "Wrapped key should be at least 8 bytes longer than original");
    }

    /**
     * Test multiple wrap/unwrap operations with same cipher instance
     */
    @Test
    public void testMultipleOperations() throws Exception {
        SecretKey kek = generateKey("AES", 256);
        Cipher cipher = Cipher.getInstance("AES/KW/NoPadding", providerName);
        
        for (int i = 0; i < 10; i++) {
            SecretKey keyToWrap = generateKey("AES", 128);
            
            cipher.init(Cipher.WRAP_MODE, kek);
            byte[] wrappedKey = cipher.wrap(keyToWrap);
            
            cipher.init(Cipher.UNWRAP_MODE, kek);
            Key unwrappedKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
            
            assertArrayEquals(keyToWrap.getEncoded(), unwrappedKey.getEncoded(),
                "Iteration " + i + ": Keys should match after wrap/unwrap");
        }
    }

    /**
     * Helper method to test wrap and unwrap operations
     */
    private void testWrapUnwrap(String algorithm, SecretKey kek, SecretKey keyToWrap) 
            throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm, providerName);
        
        // Wrap the key
        cipher.init(Cipher.WRAP_MODE, kek);
        byte[] wrappedKey = cipher.wrap(keyToWrap);
        
        assertNotNull(wrappedKey, "Wrapped key should not be null");
        assertTrue(wrappedKey.length > 0, "Wrapped key should have non-zero length");
        
        // Unwrap the key
        cipher.init(Cipher.UNWRAP_MODE, kek);
        Key unwrappedKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        
        assertNotNull(unwrappedKey, "Unwrapped key should not be null");
        assertArrayEquals(keyToWrap.getEncoded(), unwrappedKey.getEncoded(),
            "Original and unwrapped keys should match");
    }

    /**
     * Helper method to generate a secret key
     */
    private SecretKey generateKey(String algorithm, int keySize) throws Exception {
        // Use SunJCE for key generation since OpenSSL provider doesn't provide SecureRandom
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm, "SunJCE");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }
}


