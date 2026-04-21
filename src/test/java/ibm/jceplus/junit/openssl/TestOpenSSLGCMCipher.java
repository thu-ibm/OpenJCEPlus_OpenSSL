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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.StringReader;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test AES/GCM cipher using OpenSSL backend via configuration file.
 * This mirrors the CCM-style OpenSSL test approach and validates the
 * provider-facing GCM path instead of a nonexistent direct wrapper class.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestOpenSSLGCMCipher {

    private Provider testProvider;

    private static final String OPENSSL_CONFIG =
            "name = OpenSSL-GCM-Test\n" +
            "description = OpenJCEPlus Provider with OpenSSL Backend for AES-GCM Testing\n" +
            "backend = OpenSSL\n" +
            "Service.Cipher.AES/GCM/NoPadding = com.ibm.crypto.plus.provider.AESGCMCipher\n" +
            "Service.AlgorithmParameters.GCM = com.ibm.crypto.plus.provider.GCMParameters\n" +
            "Service.AlgorithmParameterGenerator.GCM = com.ibm.crypto.plus.provider.GCMParameterGenerator\n" +
            "Service.KeyGenerator.AES = com.ibm.crypto.plus.provider.AESKeyGenerator\n";

    @BeforeAll
    public void setUp() {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            if (provider.getName().startsWith("OpenSSL-GCM-Test")) {
                Security.removeProvider(provider.getName());
            }
        }

        try {
            ProviderServiceReader reader =
                    new ProviderServiceReader(new BufferedReader(new StringReader(OPENSSL_CONFIG)));

            testProvider = new OpenJCEPlus(reader);
            Security.addProvider(testProvider);

            System.out.println("========================================");
            System.out.println("AES/GCM OpenSSL Backend Test");
            System.out.println("========================================");
            System.out.println("Provider: " + testProvider.getName());
            System.out.println("Backend:  " + ((OpenJCEPlus) testProvider).getSelectedBackend());
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

    @Test
    public void testAESGCM_128_WithAAD() throws Exception {
        System.out.println("Test: AES/GCM with 128-bit key and AAD");

        assertEquals("OpenSSL", ((OpenJCEPlus) testProvider).getSelectedBackend());

        byte[] keyBytes = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[] {
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B
        };

        byte[] aad = "Additional authenticated data".getBytes("UTF-8");
        byte[] plaintext = "Testing AES-GCM with OpenSSL backend!".getBytes("UTF-8");

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext);
        assertNotNull(ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertNotNull(decrypted);
        assertArrayEquals(plaintext, decrypted);

        System.out.println("  \u2713 Encryption/Decryption with AAD: SUCCESS");
        System.out.println("  Key size:    128 bits");
        System.out.println("  Tag length:  128 bits");
        System.out.println("  IV length:   " + iv.length + " bytes");
        System.out.println("  AAD length:  " + aad.length + " bytes");
        System.out.println();
    }

    @Test
    public void testAESGCM_256_NoAAD() throws Exception {
        System.out.println("Test: AES/GCM with 256-bit key and no AAD");

        byte[] keyBytes = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[] {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B
        };

        byte[] plaintext = "AES-GCM provides authenticated encryption.".getBytes("UTF-8");

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        assertNotNull(ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertArrayEquals(plaintext, decrypted);

        System.out.println("  \u2713 Encryption/Decryption without AAD: SUCCESS");
        System.out.println("  Key size:    256 bits");
        System.out.println("  Tag length:  128 bits");
        System.out.println();
    }

    @Test
    public void testAESGCM_TamperedCiphertext() throws Exception {
        System.out.println("Test: AES/GCM authentication failure on tampered ciphertext");

        byte[] keyBytes = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[] {
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B
        };

        byte[] plaintext = "This GCM ciphertext will be tampered with.".getBytes("UTF-8");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        ciphertext[ciphertext.length - 1] ^= 0x01;

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        try {
            cipher.doFinal(ciphertext);
            fail("Should throw exception for tampered ciphertext");
        } catch (Exception exception) {
            System.out.println("  \u2713 Authentication failure detected: SUCCESS");
            System.out.println("  Exception: " + exception.getClass().getSimpleName());
            System.out.println();
        }
    }

    @Test
    public void testAESGCM_WrongAAD() throws Exception {
        System.out.println("Test: AES/GCM authentication failure with wrong AAD");

        byte[] keyBytes = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[] {
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
                0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B
        };

        byte[] aad = "expected aad".getBytes("UTF-8");
        byte[] wrongAad = "wrong aad".getBytes("UTF-8");
        byte[] plaintext = "AAD mismatch should fail authentication.".getBytes("UTF-8");

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", testProvider);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext);

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        cipher.updateAAD(wrongAad);

        try {
            cipher.doFinal(ciphertext);
            fail("Should throw exception for wrong AAD");
        } catch (Exception exception) {
            System.out.println("  \u2713 Wrong AAD failure detected: SUCCESS");
            System.out.println("  Exception: " + exception.getClass().getSimpleName());
            System.out.println();
        }
    }
}


