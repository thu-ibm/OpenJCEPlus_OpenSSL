/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openssl;

import com.ibm.crypto.plus.provider.OpenJCEPlus;
import com.ibm.crypto.plus.provider.ProviderServiceReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.Provider;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Test AES encryption/decryption using OpenSSL backend via configuration file.
 * This test demonstrates the PR #1167 config file mechanism working with actual
 * OpenSSL native cryptographic operations.
 */
public class TestAESOpenSSLConfig {

    private Provider testProvider;
    private static final String OPENSSL_CONFIG =
        "name = OpenSSL-AES-Test\n" +
        "description = OpenJCEPlus Provider with OpenSSL Backend for AES Testing\n" +
        "backend = OpenSSL\n" +
        "Service.Cipher.AES = com.ibm.crypto.plus.provider.AESCipher\n" +
        "Service.Cipher.AES/CBC/PKCS5Padding = com.ibm.crypto.plus.provider.AESCipher\n" +
        "Service.Cipher.AES/ECB/PKCS5Padding = com.ibm.crypto.plus.provider.AESCipher\n" +
        "Service.Cipher.AES/GCM/NoPadding = com.ibm.crypto.plus.provider.AESGCMCipher\n" +
        "Service.KeyGenerator.AES = com.ibm.crypto.plus.provider.AESKeyGenerator\n";

    @BeforeEach
    public void setUp() {
        // Clean up any existing test providers
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().startsWith("OpenSSL-AES-Test")) {
                Security.removeProvider(p.getName());
            }
        }
    }

    @AfterEach
    public void tearDown() {
        if (testProvider != null) {
            Security.removeProvider(testProvider.getName());
            testProvider = null;
        }
    }

    /**
     * Test AES/ECB/PKCS5Padding encryption and decryption with OpenSSL backend.
     */
    @Test
    public void testAESECBWithOpenSSL() throws Exception {
        // Create provider with OpenSSL backend via config
        ProviderServiceReader reader = new ProviderServiceReader(
            new BufferedReader(new StringReader(OPENSSL_CONFIG))
        );
        
        testProvider = new OpenJCEPlus(reader);
        Security.addProvider(testProvider);
        
        // Verify backend selection
        assertEquals("OpenSSL", ((OpenJCEPlus)testProvider).getSelectedBackend());
        
        // Use a pre-generated AES key (128-bit) to avoid needing SecureRandom
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        assertNotNull(key);
        assertEquals(16, key.getEncoded().length); // 128 bits = 16 bytes
        
        // Test data
        String plaintext = "Hello OpenSSL Backend! This is a test of AES encryption.";
        byte[] plaintextBytes = plaintext.getBytes("UTF-8");
        
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length > plaintextBytes.length); // Due to padding
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertNotNull(decrypted);
        assertArrayEquals(plaintextBytes, decrypted);
        
        // Verify decrypted text
        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(plaintext, decryptedText);
        
        System.out.println("✓ AES/ECB/PKCS5Padding with OpenSSL backend: SUCCESS");
        System.out.println("  Original:  " + plaintext);
        System.out.println("  Encrypted: " + bytesToHex(ciphertext));
        System.out.println("  Decrypted: " + decryptedText);
    }

    /**
     * Test AES/CBC/PKCS5Padding encryption and decryption with OpenSSL backend.
     */
    @Test
    public void testAESCBCWithOpenSSL() throws Exception {
        // Create provider with OpenSSL backend via config
        ProviderServiceReader reader = new ProviderServiceReader(
            new BufferedReader(new StringReader(OPENSSL_CONFIG))
        );
        
        testProvider = new OpenJCEPlus(reader);
        Security.addProvider(testProvider);
        
        // Verify backend selection
        assertEquals("OpenSSL", ((OpenJCEPlus)testProvider).getSelectedBackend());
        
        // Use a pre-generated AES key (256-bit) to avoid needing SecureRandom
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
        SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        assertNotNull(key);
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes
        
        // Use a pre-generated IV to avoid needing SecureRandom
        byte[] iv = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Test data
        String plaintext = "Testing AES-256-CBC with OpenSSL backend!";
        byte[] plaintextBytes = plaintext.getBytes("UTF-8");
        
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        assertNotNull(ciphertext);
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertNotNull(decrypted);
        assertArrayEquals(plaintextBytes, decrypted);
        
        // Verify decrypted text
        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(plaintext, decryptedText);
        
        System.out.println("✓ AES/CBC/PKCS5Padding with OpenSSL backend: SUCCESS");
        System.out.println("  Key size:  256 bits");
        System.out.println("  IV:        " + bytesToHex(iv));
        System.out.println("  Original:  " + plaintext);
        System.out.println("  Decrypted: " + decryptedText);
    }

    /**
     * Test AES/GCM/NoPadding encryption and decryption with OpenSSL backend.
     */
    @Test
    public void testAESGCMWithOpenSSL() throws Exception {
        // Create provider with OpenSSL backend via config
        ProviderServiceReader reader = new ProviderServiceReader(
            new BufferedReader(new StringReader(OPENSSL_CONFIG))
        );
        
        testProvider = new OpenJCEPlus(reader);
        Security.addProvider(testProvider);
        
        // Verify backend selection
        assertEquals("OpenSSL", ((OpenJCEPlus)testProvider).getSelectedBackend());
        
        // Use a pre-generated AES key (128-bit) to avoid needing SecureRandom
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        assertNotNull(key);
        
        // Use a pre-generated IV for GCM (12 bytes recommended)
        byte[] iv = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B
        };
        
        // Test data
        String plaintext = "AES-GCM provides authenticated encryption!";
        byte[] plaintextBytes = plaintext.getBytes("UTF-8");
        
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", testProvider);
        javax.crypto.spec.GCMParameterSpec gcmSpec = 
            new javax.crypto.spec.GCMParameterSpec(128, iv); // 128-bit auth tag
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        assertNotNull(ciphertext);
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertNotNull(decrypted);
        assertArrayEquals(plaintextBytes, decrypted);
        
        // Verify decrypted text
        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(plaintext, decryptedText);
        
        System.out.println("✓ AES/GCM/NoPadding with OpenSSL backend: SUCCESS");
        System.out.println("  Mode:      Authenticated Encryption");
        System.out.println("  Original:  " + plaintext);
        System.out.println("  Decrypted: " + decryptedText);
    }

    /**
     * Test that config file correctly selects OpenSSL backend over OCK.
     */
    @Test
    public void testBackendSelectionViaConfig() throws Exception {
        // Create provider with OpenSSL backend
        ProviderServiceReader opensslReader = new ProviderServiceReader(
            new BufferedReader(new StringReader(OPENSSL_CONFIG))
        );
        OpenJCEPlus opensslProvider = new OpenJCEPlus(opensslReader);
        
        // Verify OpenSSL backend is selected
        assertEquals("OpenSSL", opensslProvider.getSelectedBackend());
        assertTrue(opensslProvider.getName().contains("OpenSSL"));
        
        // Create provider with OCK backend
        String ockConfig = 
            "name = OCK-AES-Test\n" +
            "description = OpenJCEPlus Provider with OCK Backend\n" +
            "backend = OCK\n" +
            "Service.Cipher.AES = com.ibm.crypto.plus.provider.AESCipher$General\n";
        
        ProviderServiceReader ockReader = new ProviderServiceReader(
            new BufferedReader(new StringReader(ockConfig))
        );
        OpenJCEPlus ockProvider = new OpenJCEPlus(ockReader);
        
        // Verify OCK backend is selected
        assertEquals("OCK", ockProvider.getSelectedBackend());
        assertTrue(ockProvider.getName().contains("OCK"));
        
        // Verify they are different instances with different backends
        assertNotEquals(opensslProvider.getSelectedBackend(), 
                       ockProvider.getSelectedBackend());
        
        System.out.println("✓ Backend selection via config file: SUCCESS");
        System.out.println("  OpenSSL Provider: " + opensslProvider.getName() + 
                         " (backend=" + opensslProvider.getSelectedBackend() + ")");
        System.out.println("  OCK Provider:     " + ockProvider.getName() + 
                         " (backend=" + ockProvider.getSelectedBackend() + ")");
    }

    /**
     * Helper method to convert bytes to hex string for display.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, 16); i++) {
            sb.append(String.format("%02X", bytes[i]));
            if (i < Math.min(bytes.length, 16) - 1) sb.append(" ");
        }
        if (bytes.length > 16) {
            sb.append("...");
        }
        return sb.toString();
    }
}


