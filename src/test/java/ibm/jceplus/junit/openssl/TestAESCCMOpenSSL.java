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
import ibm.security.internal.spec.CCMParameterSpec;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.Provider;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

/**
 * Test AES/CCM cipher using OpenSSL backend via configuration file.
 * This test demonstrates AES-CCM authenticated encryption with OpenSSL native operations.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestAESCCMOpenSSL {

    private Provider testProvider;
    private static final String OPENSSL_CONFIG =
        "name = OpenSSL-CCM-Test\n" +
        "description = OpenJCEPlus Provider with OpenSSL Backend for AES-CCM Testing\n" +
        "backend = OpenSSL\n" +
        "Service.Cipher.AES/CCM/NoPadding = com.ibm.crypto.plus.provider.AESCCMCipher\n" +
        "Service.AlgorithmParameters.CCM = com.ibm.crypto.plus.provider.CCMParameters\n" +
        "Service.AlgorithmParameterGenerator.CCM = com.ibm.crypto.plus.provider.CCMParameterGenerator\n" +
        "Service.KeyGenerator.AES = com.ibm.crypto.plus.provider.AESKeyGenerator\n";

    @BeforeAll
    public void setUp() {
        // Clean up any existing test providers
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            if (p.getName().startsWith("OpenSSL-CCM-Test")) {
                Security.removeProvider(p.getName());
            }
        }
        
        try {
            // Create provider with OpenSSL backend via config
            ProviderServiceReader reader = new ProviderServiceReader(
                new BufferedReader(new StringReader(OPENSSL_CONFIG))
            );
            
            testProvider = new OpenJCEPlus(reader);
            Security.addProvider(testProvider);
            
            System.out.println("========================================");
            System.out.println("AES/CCM OpenSSL Backend Test");
            System.out.println("========================================");
            System.out.println("Provider: " + testProvider.getName());
            System.out.println("Backend:  " + ((OpenJCEPlus)testProvider).getSelectedBackend());
            System.out.println();
        } catch (Exception e) {
            fail("Failed to initialize OpenSSL provider: " + e.getMessage());
        }
    }

    @AfterAll
    public void tearDown() {
        if (testProvider != null) {
            Security.removeProvider(testProvider.getName());
            testProvider = null;
        }
    }

    /**
     * Test AES/CCM encryption and decryption with 128-bit tag.
     */
    @Test
    public void testAESCCM_128BitTag() throws Exception {
        System.out.println("Test: AES/CCM with 128-bit authentication tag");
        
        // Verify backend selection
        assertEquals("OpenSSL", ((OpenJCEPlus)testProvider).getSelectedBackend());
        
        // Use a pre-generated AES-128 key
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        // Use a pre-generated nonce (13 bytes is recommended for CCM)
        byte[] nonce = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C
        };
        
        // Additional Authenticated Data (AAD)
        byte[] aad = "Additional data for authentication".getBytes("UTF-8");
        
        // Test data
        String plaintext = "Testing AES-CCM with OpenSSL backend!";
        byte[] plaintextBytes = plaintext.getBytes("UTF-8");
        
        // Create CCM parameter spec with 128-bit tag
        CCMParameterSpec ccmSpec = new CCMParameterSpec(128, nonce);
        
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, ccmSpec);
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        assertNotNull(ciphertext);
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ccmSpec);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertNotNull(decrypted);
        assertArrayEquals(plaintextBytes, decrypted);
        
        // Verify decrypted text
        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(plaintext, decryptedText);
        
        System.out.println("  ✓ Encryption/Decryption: SUCCESS");
        System.out.println("  Key size:    128 bits");
        System.out.println("  Tag length:  128 bits");
        System.out.println("  Nonce:       " + bytesToHex(nonce));
        System.out.println("  AAD length:  " + aad.length + " bytes");
        System.out.println("  Original:    " + plaintext);
        System.out.println("  Decrypted:   " + decryptedText);
        System.out.println();
    }

    /**
     * Test AES/CCM encryption and decryption with 96-bit tag.
     */
    @Test
    public void testAESCCM_96BitTag() throws Exception {
        System.out.println("Test: AES/CCM with 96-bit authentication tag");
        
        // Use a pre-generated AES-256 key
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        // Use a pre-generated nonce
        byte[] nonce = new byte[] {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C
        };
        
        // Test data
        String plaintext = "AES-CCM provides authenticated encryption with associated data!";
        byte[] plaintextBytes = plaintext.getBytes("UTF-8");
        
        // Create CCM parameter spec with 96-bit tag
        CCMParameterSpec ccmSpec = new CCMParameterSpec(96, nonce);
        
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, ccmSpec);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        assertNotNull(ciphertext);
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ccmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertNotNull(decrypted);
        assertArrayEquals(plaintextBytes, decrypted);
        
        // Verify decrypted text
        String decryptedText = new String(decrypted, "UTF-8");
        assertEquals(plaintext, decryptedText);
        
        System.out.println("  ✓ Encryption/Decryption: SUCCESS");
        System.out.println("  Key size:    256 bits");
        System.out.println("  Tag length:  96 bits");
        System.out.println("  Original:    " + plaintext);
        System.out.println("  Decrypted:   " + decryptedText);
        System.out.println();
    }

    /**
     * Test AES/CCM with tampered ciphertext (should fail authentication).
     */
    @Test
    public void testAESCCM_TamperedCiphertext() throws Exception {
        System.out.println("Test: AES/CCM authentication failure on tampered ciphertext");
        
        // Use a pre-generated AES-128 key
        byte[] keyBytes = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        // Use a pre-generated nonce
        byte[] nonce = new byte[] {
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C
        };
        
        // Test data
        String plaintext = "This message will be tampered with!";
        byte[] plaintextBytes = plaintext.getBytes("UTF-8");
        
        // Create CCM parameter spec
        CCMParameterSpec ccmSpec = new CCMParameterSpec(128, nonce);
        
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, ccmSpec);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        
        // Tamper with the ciphertext
        ciphertext[0] ^= 0x01;
        
        // Try to decrypt - should fail authentication
        cipher.init(Cipher.DECRYPT_MODE, key, ccmSpec);
        
        // Use try-catch instead of assertThrows to avoid JUnit API access issues
        try {
            cipher.doFinal(ciphertext);
            fail("Should throw exception for tampered ciphertext");
        } catch (Exception exception) {
            // Expected exception - authentication should fail
            System.out.println("  ✓ Authentication failure detected: SUCCESS");
            System.out.println("  Exception: " + exception.getClass().getSimpleName());
            System.out.println();
        }
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

