/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.ProviderException;
import sun.security.util.Debug;
/**
 * Native method declarations for OpenSSL backend.
 * This class declares all JNI methods that call into the OpenSSL native library.
 * 
 * IMPORTANT: All method signatures must exactly match the native C implementations
 * in src/main/native/openssl/*.c files.
 */
final class NativeOpenSSLImplementation {

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    // Default OpenSSL library names
    private static final String OPENSSL_LIBRARY_NAME = "libssl-3-x64";
    private static final String CRYPTO_LIBRARY_NAME = "libcrypto-3-x64";
    private static final String JGSKIT_LIBRARY_NAME = "jgskit_openssl";
    private static String osName = null;
    private static String osArch = null;

    static {
        // Initialize OS properties before library loading
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        
        // Preload OpenSSL libraries first
        preloadOpenSSL();
        // Then load our JNI bridge library
        preloadJGskit();
    }

    public static String getOsName() {
        return osName;
    }

    public static String getOsArch() {
        return osArch;
    }

    static String getOpenSSLLoadPath() {
        // For OpenSSL DLLs, check OPENSSL_HOME environment variable first
        String opensslHome = System.getenv("OPENSSL_HOME");
        if (opensslHome != null && !opensslHome.trim().isEmpty()) {
            String opensslPath;
            if (osName.startsWith("Windows")) {
                opensslPath = opensslHome + File.separator + "bin";
            } else {
                opensslPath = opensslHome + File.separator + "lib";
            }
            if (debug != null) {
                debug.println("Loading OpenSSL DLLs from OPENSSL_HOME: " + opensslPath);
            }
            return opensslPath;
        }

        // Fall back to openssl.library.path property
        String opensslOverridePath = System.getProperty("openssl.library.path");
        if (opensslOverridePath != null) {
            if (debug != null) {
                debug.println("Loading OpenSSL library using value in property openssl.library.path: "
                    + opensslOverridePath);
            }
            return opensslOverridePath;
        }
        
        if (debug != null) {
            debug.println("Library path not found for OpenSSL, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        String opensslPath;

        if (osName.startsWith("Windows")) {
            opensslPath = javaHome + File.separator + "bin";
        } else {
            opensslPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading OpenSSL library using value: " + opensslPath);
        }
        return opensslPath;
    }

    static String getJGskitLoadPath() {
        // For our JNI bridge library, check jgskit.library.path property first
        String jgskitOverridePath = System.getProperty("jgskit.library.path");
        if (jgskitOverridePath != null) {
            if (debug != null) {
                debug.println("Loading JGskit library using value in property jgskit.library.path: "
                    + jgskitOverridePath);
            }
            return jgskitOverridePath;
        }
        
        // Fall back to openssl.library.path property
        String opensslOverridePath = System.getProperty("openssl.library.path");
        if (opensslOverridePath != null) {
            if (debug != null) {
                debug.println("Loading JGskit library using value in property openssl.library.path: "
                    + opensslOverridePath);
            }
            return opensslOverridePath;
        }
        
        // Fall back to same path as OpenSSL
        return getOpenSSLLoadPath();
    }

    static void preloadOpenSSL() {
        String opensslPath = getOpenSSLLoadPath();

        File cryptoFile = getLibraryFile(opensslPath, CRYPTO_LIBRARY_NAME);
        File sslFile = getLibraryFile(opensslPath, OPENSSL_LIBRARY_NAME);

        boolean cryptoLoaded = loadIfExists(cryptoFile);
        boolean sslLoaded = loadIfExists(sslFile);

        if (!cryptoLoaded || !sslLoaded) {
            throw new ProviderException("Could not load OpenSSL libraries for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    static void preloadJGskit() {
        String jgskitPath = getJGskitLoadPath();
        
        File jgskitFile = getLibraryFile(jgskitPath, JGSKIT_LIBRARY_NAME);
        boolean jgskitLoaded = loadIfExists(jgskitFile);
        
        if (!jgskitLoaded) {
            throw new ProviderException("Could not load " + JGSKIT_LIBRARY_NAME + " library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    private static File getLibraryFile(String path, String name) {
        if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            return new File(path, name + ".dll");
        } else if (osName.equals("Mac OS X")) {
            return new File(path, "lib" + name + ".dylib");
        } else {
            return new File(path, "lib" + name + ".so");
        }
    }

    @SuppressWarnings("restricted")
    private static boolean loadIfExists(File libraryFile) {
        String libraryName = libraryFile.getAbsolutePath();

        if (libraryFile.exists()) {
            try {
                System.load(libraryName);
                if (debug != null) {
                    debug.println("Loaded : " + libraryName);
                }
                return true;
            } catch (Error e) {
                // Rethrow serious JVM errors
                throw e;
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("Failed to load : " + libraryName);
                    e.printStackTrace(System.out);
                }
            }
        } else {
            if (debug != null) {
                debug.println("Skipping load of " + libraryName + " (file does not exist)");
            }
        }
        return false;
    }

    // =========================================================================
    // General functions
    // =========================================================================

    static public native String getLibraryBuildDate();

    // =========================================================================
    // Context functions
    // =========================================================================

    static public native long initializeOpenSSL(boolean isFIPS);
    
    static public native void cleanupOpenSSL(long contextId);

    static public native String CTX_getValue(long contextId, int valueId);

    static native long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Digest functions
    // =========================================================================

    static public native long DIGEST_create(int fipsFlag, String algorithm);

    static public native long DIGEST_copy(int fipsFlag, long digestId);

    static public native int DIGEST_update(int fipsFlag, long digestId, byte[] data,
            int offset, int length);

    static public native byte[] DIGEST_digest(int fipsFlag, long digestId);

    static public native int DIGEST_digest_and_reset(int fipsFlag, long digestId,
            byte[] digest, int digestOffset);

    static public native int DIGEST_size(int fipsFlag, long digestId);

    static public native void DIGEST_reset(int fipsFlag, long digestId);

    static public native void DIGEST_delete(int fipsFlag, long digestId);

    // =========================================================================
    // HMAC functions
    // =========================================================================

    static public native long HMAC_create(int fipsFlag, String algorithm);

    static public native int HMAC_init(int fipsFlag, long hmacId, byte[] key, int keyLen);

    static public native int HMAC_update(int fipsFlag, long hmacId, byte[] data,
            int offset, int length);

    static public native int HMAC_doFinal(int fipsFlag, long hmacId, byte[] mac,
            int macOffset);

    static public native int HMAC_size(int fipsFlag, long hmacId);

    static public native void HMAC_reset(int fipsFlag, long hmacId);

    static public native void HMAC_delete(int fipsFlag, long hmacId);

    // =========================================================================
    // HKDF functions
    // =========================================================================

    static public native byte[] HKDF_extract(int fipsFlag, String algorithm, byte[] salt,
            byte[] ikm);

    static public native byte[] HKDF_expand(int fipsFlag, String algorithm, byte[] prk,
            byte[] info, int okmLen);

    static public native byte[] HKDF_derive(int fipsFlag, String algorithm, byte[] salt,
            byte[] ikm, byte[] info, int okmLen);

    // =========================================================================
    // PBKDF2 functions
    // =========================================================================

    static public native byte[] PBKDF2_derive(int fipsFlag, String algorithm, byte[] password,
            byte[] salt, int iterations, int keyLen);

    // =========================================================================
    // Cipher functions
    // =========================================================================

    static public native long CIPHER_create(int fipsFlag, String cipher);

    static public native void CIPHER_init(int fipsFlag, long cipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv);

    static public native int CIPHER_getBlockSize(int fipsFlag, long cipherId);

    static public native int CIPHER_getKeyLength(int fipsFlag, long cipherId);

    static public native int CIPHER_getIVLength(int fipsFlag, long cipherId);

    static public native int CIPHER_encryptUpdate(int fipsFlag, long cipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset);

    static public native int CIPHER_decryptUpdate(int fipsFlag, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset);

    static public native int CIPHER_encryptFinal(int fipsFlag, long cipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset);

    static public native int CIPHER_decryptFinal(int fipsFlag, long cipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset);

    static public native void CIPHER_delete(int fipsFlag, long cipherId);

    // =========================================================================
    // Key Wrap functions
    // =========================================================================

    static public native byte[] KEYWRAP_wrap(int fipsFlag, byte[] plaintext, byte[] kek,
            boolean padding);

    static public native byte[] KEYWRAP_unwrap(int fipsFlag, byte[] wrappedKey, byte[] kek,
            boolean padding);

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    static public native void GCM_init(int fipsFlag, long cipherId, int encrypt,
            byte[] key, byte[] iv, int tagLen);

    static public native int GCM_update(int fipsFlag, long cipherId, int encrypt,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen);

    static public native int GCM_encryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);

    static public native int GCM_decryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    static public native void CCM_init(int fipsFlag, long cipherId, int encrypt,
            byte[] key, byte[] iv, int tagLen);

    static public native int CCM_update(int fipsFlag, long cipherId, int encrypt,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen);

    static public native int CCM_encryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);

    static public native int CCM_decryptFinal(int fipsFlag, long cipherId,
            byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, int aadLen, int tagLen);
}


