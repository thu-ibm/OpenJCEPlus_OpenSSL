/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeInterface;
import com.ibm.crypto.plus.provider.base.OCKException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.security.ProviderException;
public abstract class NativeOpenSSLAdapter implements NativeInterface {
    // These code values must match those defined in OpenSSLContext.h
    private static final int VALUE_ID_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_OPENSSL_INSTALL_PATH = 1;
    private static final int VALUE_OPENSSL_VERSION = 2;

    // FIPS flag constants for native calls
    private static final int FIPS_ENABLED = 1;
    private static final int FIPS_DISABLED = 0;

    // Debug logging disabled (sun.security.util.Debug not accessible in module system)
    // private static Debug debug = Debug.getInstance("jceplus");

    static final String unobtainedValue = new String();

    // whether to validate OpenSSL was loaded from JRE location
    // Can be enabled via system property for production deployments
    private static final boolean validateOpenSSLLocation =
        Boolean.getBoolean("openssl.enable.location.validation");

    // whether to validate OpenSSL version
    private static final boolean validateOpenSSLVersion = false;

    private OpenSSLContext opensslContext = null;
    private boolean opensslInitialized = false;
    private boolean fipsMode;

    private String opensslVersion = unobtainedValue;
    private String opensslInstallPath = unobtainedValue;

    private static String libraryBuildDate = unobtainedValue;
    private static final int DEFAULT_GCM_TAG_LEN = 16;
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private static final long HKDF_DUMMY_CONTEXT_ID = 1L;

    NativeOpenSSLAdapter(boolean fipsMode) {
        this.fipsMode = fipsMode;
        initializeContext();
    }

    // Initialize OpenSSL context
    private synchronized void initializeContext() {
        if (opensslInitialized) {
            return;
        }

        try {
            long opensslContextId = NativeOpenSSLImplementation.initializeOpenSSL(this.fipsMode);
            this.opensslContext = OpenSSLContext.createContext(opensslContextId, this.fipsMode);
            getLibraryBuildDate();

            if (validateOpenSSLLocation) {
                validateLibraryLocation();
            }

            if (validateOpenSSLVersion) {
                validateLibraryVersion();
            }

            this.opensslInitialized = true;
        } catch (OCKException e) {
            throw providerException("Failed to initialize OpenJCEPlus provider with OpenSSL", e);
        } catch (Throwable t) {
            ProviderException exceptionToThrow = providerException(
                    "Failed to initialize OpenJCEPlus provider with OpenSSL", t);

            if (exceptionToThrow.getCause() == null) {
                if ((t instanceof java.lang.ExceptionInInitializerError)
                        || (t instanceof java.lang.NoClassDefFoundError)) {
                    Throwable cause = t.getCause();
                    if (cause != null) {
                        t = cause;
                    }
                }

                String message = t.getMessage();
                if ((message != null) && (message.length() > 0)) {
                    exceptionToThrow.initCause(new ProviderException(t.getMessage()));
                }
            }

            // Debug disabled - sun.security.util.Debug not accessible
            // if (debug != null) {
            //     exceptionToThrow.printStackTrace(System.out);
            // }

            throw exceptionToThrow;
        }
    }

    // Get OpenSSL context for crypto operations
    OpenSSLContext getOpenSSLContext() {
        if (!opensslInitialized) {
            initializeContext();
        }
        return opensslContext;
    }

    @Override
    public String getLibraryVersion() throws OCKException {
        if (opensslVersion == unobtainedValue) {
            obtainOpenSSLVersion();
        }
        return opensslVersion;
    }

    @Override
    public String getLibraryInstallPath() throws OCKException {
        if (opensslInstallPath == unobtainedValue) {
            obtainOpenSSLInstallPath();
        }
        return opensslInstallPath;
    }

    private synchronized void obtainOpenSSLVersion() throws OCKException {
        if (opensslVersion == unobtainedValue) {
            opensslVersion = CTX_getValue(VALUE_OPENSSL_VERSION);
        }
    }

    private synchronized void obtainOpenSSLInstallPath() throws OCKException {
        if (opensslInstallPath == unobtainedValue) {
            opensslInstallPath = CTX_getValue(VALUE_OPENSSL_INSTALL_PATH);
        }
    }

    static public ProviderException providerException(String message, Throwable opensslException) {
        ProviderException providerException = new ProviderException(message, opensslException);
        setOpenSSLExceptionCause(providerException, opensslException);
        return providerException;
    }

    static public void setOpenSSLExceptionCause(Exception exception, Throwable opensslException) {
        // Debug disabled - sun.security.util.Debug not accessible
        // Always set cause for proper exception chaining
        if (exception.getCause() == null) {
            exception.initCause(opensslException);
        }
    }
    
    // Get FIPS flag for native calls
    private int getFipsFlag() {
        return this.fipsMode ? FIPS_ENABLED : FIPS_DISABLED;
    }

    @Override
    public void validateLibraryLocation() throws ProviderException, OCKException {
        // Skip validation if disabled via system property
        if (!validateOpenSSLLocation) {
            return;
        }
        
        try {
            String opensslLoadPath = new File(NativeOpenSSLImplementation.getOpenSSLLoadPath()).getCanonicalPath();
            String opensslInstallPath = new File(getLibraryInstallPath()).getCanonicalPath();
            if (!opensslInstallPath.startsWith(opensslLoadPath)) {
                throw new ProviderException("OpenSSL library was loaded from an external location: "
                    + opensslInstallPath + " (expected under: " + opensslLoadPath + ")");
            }
        } catch (java.io.IOException e) {
            throw new ProviderException("Failed to validate OpenSSL library location", e);
        }
    }

    @Override
    public void validateLibraryVersion() throws ProviderException, OCKException {
        // OpenSSL version validation can be added here if needed
        // For now, we skip this as OpenSSL doesn't have ICCSIG.txt equivalent
    }

    @Override
    public String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = NativeOpenSSLImplementation.getLibraryBuildDate();
        }
        return libraryBuildDate;
    }

    @Override
    public long initializeOCK(boolean isFIPS) throws OCKException {
        // Method name is inherited from the shared NativeInterface contract.
        // The OpenSSL backend initializes its own native library/context here.
        return NativeOpenSSLImplementation.initializeOpenSSL(isFIPS);
    }

    @Override
    public String CTX_getValue(int valueId) throws OCKException {
        return NativeOpenSSLImplementation.CTX_getValue(opensslContext.getId(), valueId);
    }

    @Override
    public long getByteBufferPointer(ByteBuffer b) {
        return NativeOpenSSLImplementation.getByteBufferPointer(b);
    }

    // =========================================================================
    // Cipher Functions
    // =========================================================================

    @Override
    public long CIPHER_create(String cipher) throws OCKException {
        return NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipher);
    }

    @Override
    public void CIPHER_init(long cipherId, int isEncrypt, int paddingId, byte[] key, byte[] iv) throws OCKException {
        NativeOpenSSLImplementation.CIPHER_init(getFipsFlag(), cipherId, isEncrypt, paddingId, key, iv);
    }

    @Override
    public int CIPHER_encryptUpdate(long cipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean needsReinit) throws OCKException {
        // OpenSSL native doesn't use needsReinit.
        return NativeOpenSSLImplementation.CIPHER_encryptUpdate(getFipsFlag(), cipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int CIPHER_decryptUpdate(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OCKException {
        // OpenSSL native doesn't use needsReinit.
        return NativeOpenSSLImplementation.CIPHER_decryptUpdate(getFipsFlag(), cipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public int CIPHER_encryptFinal(long cipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws OCKException {
        // OpenSSL native doesn't use needsReinit.
        return NativeOpenSSLImplementation.CIPHER_encryptFinal(getFipsFlag(), cipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int CIPHER_decryptFinal(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) throws OCKException {
        // OpenSSL native doesn't use needsReinit.
        return NativeOpenSSLImplementation.CIPHER_decryptFinal(getFipsFlag(), cipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public void CIPHER_delete(long cipherId) throws OCKException {
        NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
    }

    @Override
    public byte[] CIPHER_KeyWraporUnwrap(byte[] key, byte[] KEK, int type) throws OCKException {
        // OpenSSL has separate wrap/unwrap methods.
        // type bit 0: 1 = wrap, 0 = unwrap
        // type bit 2: 1 = RFC 5649 padding, 0 = RFC 3394 no padding
        boolean padding = (type & 0x4) != 0;
        boolean wrap = (type & 0x1) != 0;

        if (wrap) {
            return NativeOpenSSLImplementation.KEYWRAP_wrap(getFipsFlag(), key, KEK, padding);
        } else {
            return NativeOpenSSLImplementation.KEYWRAP_unwrap(getFipsFlag(), key, KEK, padding);
        }
    }

    // =========================================================================
    // Methods not yet implemented in OpenSSL - throw UnsupportedOperationException
    // =========================================================================

    @Override
    public void RAND_nextBytes(byte[] buffer) throws OCKException {
        throw new UnsupportedOperationException("RAND_nextBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public void RAND_setSeed(byte[] seed) throws OCKException {
        throw new UnsupportedOperationException("RAND_setSeed not yet implemented in OpenSSL backend");
    }

    @Override
    public void RAND_generateSeed(byte[] seed) throws OCKException {
        throw new UnsupportedOperationException("RAND_generateSeed not yet implemented in OpenSSL backend");
    }

    @Override
    public long EXTRAND_create(String algName) throws OCKException {
        throw new UnsupportedOperationException("EXTRAND_create not yet implemented in OpenSSL backend");
    }

    @Override
    public void EXTRAND_nextBytes(long prngContextId, byte[] buffer) throws OCKException {
        throw new UnsupportedOperationException("EXTRAND_nextBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public void EXTRAND_setSeed(long prngContextId, byte[] seed) throws OCKException {
        throw new UnsupportedOperationException("EXTRAND_setSeed not yet implemented in OpenSSL backend");
    }

    @Override
    public void EXTRAND_delete(long prngContextId) throws OCKException {
        throw new UnsupportedOperationException("EXTRAND_delete not yet implemented in OpenSSL backend");
    }

    @Override
    public void CIPHER_clean(long cipherId) throws OCKException {
        throw new UnsupportedOperationException("CIPHER_clean not yet implemented in OpenSSL backend");
    }

    @Override
    public void CIPHER_setPadding(long cipherId, int paddingId) throws OCKException {
        throw new UnsupportedOperationException("CIPHER_setPadding not yet implemented in OpenSSL backend");
    }

    @Override
    public int CIPHER_getBlockSize(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getBlockSize(getFipsFlag(), cipherId);
    }

    @Override
    public int CIPHER_getKeyLength(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getKeyLength(getFipsFlag(), cipherId);
    }

    @Override
    public int CIPHER_getIVLength(long cipherId) {
        return NativeOpenSSLImplementation.CIPHER_getIVLength(getFipsFlag(), cipherId);
    }

    @Override
    public int CIPHER_getOID(long cipherId) {
        throw new UnsupportedOperationException("CIPHER_getOID not yet implemented in OpenSSL backend");
    }

    @Override
    public long checkHardwareSupport() {
        throw new UnsupportedOperationException("checkHardwareSupport not yet implemented in OpenSSL backend");
    }

    @Override
    public int z_kmc_native(byte[] input, int inputOffset, byte[] output, int outputOffset, long paramPointer,
            int inputLength, int mode) {
        throw new UnsupportedOperationException("z_kmc_native not yet implemented in OpenSSL backend");
    }

    /**
     * Validates and normalizes a digest algorithm name.
     * Only allows approved algorithm names to prevent potential security issues.
     *
     * @param algorithm The algorithm name to validate and normalize
     * @return The normalized algorithm name (hyphens removed)
     * @throws IllegalArgumentException if algorithm is null or not in approved list
     */
    private String normalizeDigestAlgorithm(String algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Digest algorithm must not be null");
        }
        
        // Normalize by removing hyphens
        String normalized = algorithm.replace("-", "");
        
        // Whitelist of approved digest algorithms
        // This prevents potential issues from malicious algorithm names
        switch (normalized.toUpperCase()) {
            case "SHA1":
            case "SHA224":
            case "SHA256":
            case "SHA384":
            case "SHA512":
            case "SHA512224":
            case "SHA512256":
            case "SHA3224":
            case "SHA3256":
            case "SHA3384":
            case "SHA3512":
                return normalized;
            default:
                throw new IllegalArgumentException("Unsupported or invalid digest algorithm: " + algorithm);
        }
    }

    private String hkdfDigestAlgorithm = "SHA256";

    /**
     * Creates an HKDF context for key derivation operations.
     *
     * Note: OpenSSL's HKDF implementation is stateless, unlike other cryptographic
     * operations that maintain state across multiple calls. Therefore, this method
     * returns a dummy context ID (HKDF_DUMMY_CONTEXT_ID) while storing the digest
     * algorithm in the adapter's state. The actual HKDF operations (extract, expand,
     * derive) are performed as single-shot operations using the stored algorithm.
     *
     * @param digestAlgo The digest algorithm to use for HKDF (e.g., "SHA-256")
     * @return A dummy context ID for API compatibility
     * @throws OCKException if the digest algorithm is invalid
     */
    @Override
    public long HKDF_create(String digestAlgo) throws OCKException {
        this.hkdfDigestAlgorithm = normalizeDigestAlgorithm(digestAlgo);
        // OpenSSL HKDF is stateless, return a dummy ID while retaining the algorithm in adapter state.
        return HKDF_DUMMY_CONTEXT_ID;
    }

    @Override
    public byte[] HKDF_extract(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen) throws OCKException {
        return NativeOpenSSLImplementation.HKDF_extract(getFipsFlag(), hkdfDigestAlgorithm, saltBytes, inKey);
    }

    @Override
    public byte[] HKDF_expand(long hkdfId, byte[] prkBytes, long prkBytesLen, byte[] info, long infoLen, long okmLen) throws OCKException {
        return NativeOpenSSLImplementation.HKDF_expand(getFipsFlag(), hkdfDigestAlgorithm, prkBytes, info, (int) okmLen);
    }

    @Override
    public byte[] HKDF_derive(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen) throws OCKException {
        return NativeOpenSSLImplementation.HKDF_derive(getFipsFlag(), hkdfDigestAlgorithm, saltBytes, inKey, info, (int) okmLen);
    }

    @Override
    public void HKDF_delete(long hkdfId) throws OCKException {
        // OpenSSL HKDF is stateless - nothing to delete
    }

    @Override
    public int HKDF_size(long hkdfId) throws OCKException {
        throw new UnsupportedOperationException("HKDF_size not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt, int iterations, int keyLength) throws OCKException {
        return NativeOpenSSLImplementation.PBKDF2_derive(getFipsFlag(), hashAlgorithm, password, salt, iterations, keyLength);
    }

    @Override
    public long MLKEY_generate(String cipherName) throws OCKException {
        throw new UnsupportedOperationException("MLKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long MLKEY_createPrivateKey(String cipherName, byte[] privateKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("MLKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long MLKEY_createPublicKey(String cipherName, byte[] publicKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("MLKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] MLKEY_getPrivateKeyBytes(long mlkeyId) throws OCKException {
        throw new UnsupportedOperationException("MLKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] MLKEY_getPublicKeyBytes(long mlkeyId) throws OCKException {
        throw new UnsupportedOperationException("MLKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public void MLKEY_delete(long mlkeyId) {
        throw new UnsupportedOperationException("MLKEY_delete not yet implemented in OpenSSL backend");
    }

    @Override
    public void KEM_encapsulate(long pKeyId, byte[] wrappedKey, byte[] randomKey) throws OCKException {
        throw new UnsupportedOperationException("KEM_encapsulate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] KEM_decapsulate(long pKeyId, byte[] wrappedKey) throws OCKException {
        throw new UnsupportedOperationException("KEM_decapsulate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] PQC_SIGNATURE_sign(long pKeyId, byte[] data) throws OCKException {
        throw new UnsupportedOperationException("PQC_SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean PQC_SIGNATURE_verify(long pKeyId, byte[] sigBytes, byte[] data) throws OCKException {
        throw new UnsupportedOperationException("PQC_SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // POLY1305CIPHER Functions - Not yet implemented
    // =========================================================================

    @Override
    public long POLY1305CIPHER_create(String cipher) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_create not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_init(long cipherId, int isEncrypt, byte[] key, byte[] iv) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_init not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_clean(long cipherId) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_clean not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_setPadding(long cipherId, int paddingId) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_setPadding not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getBlockSize(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getBlockSize not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getKeyLength(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getKeyLength not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getIVLength(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getIVLength not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_getOID(long cipherId) {
        throw new UnsupportedOperationException("POLY1305CIPHER_getOID not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_encryptUpdate(long cipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_encryptUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_decryptUpdate(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_decryptUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_encryptFinal(long cipherId, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] tag) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_encryptFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public int POLY1305CIPHER_decryptFinal(long cipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] tag) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_decryptFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public void POLY1305CIPHER_delete(long cipherId) throws OCKException {
        throw new UnsupportedOperationException("POLY1305CIPHER_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // GCM Functions
    // =========================================================================

    @Override
    public long do_GCM_checkHardwareGCMSupport() {
        return -1;
    }

    @Override
    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        throw new UnsupportedOperationException("do_GCM_encryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OCKException {
        throw new UnsupportedOperationException("do_GCM_encryptFastJNI not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        throw new UnsupportedOperationException("do_GCM_decryptFastJNI_WithHardwareSupport not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen, int ivLen, int ciphertextOffset, int ciphertextLen,
            int plainOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws OCKException {
        throw new UnsupportedOperationException("do_GCM_decryptFastJNI not supported by OpenSSL backend");
    }

    @Override
    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset,
            int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws OCKException {
        try {
            String cipherAlg = getAESCipherAlgorithm(keyLen, "GCM");
            long cipherId = NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipherAlg);
            try {
                NativeOpenSSLImplementation.GCM_init(getFipsFlag(), cipherId, 1, key, iv, tagLen);
                byte[] combinedOutput = new byte[inLen + tagLen];
                int totalLen = NativeOpenSSLImplementation.GCM_encryptFinal(getFipsFlag(), cipherId,
                        input, inOffset, inLen, combinedOutput, 0, aad, aadLen, tagLen);

                int cipherLen = Math.max(0, totalLen - tagLen);
                System.arraycopy(combinedOutput, 0, ciphertext, ciphertextOffset, cipherLen);
                System.arraycopy(combinedOutput, cipherLen, tag, 0, tagLen);
                return 0;
            } finally {
                NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
            }
        } catch (IllegalArgumentException e) {
            throw new OCKException("Invalid GCM encryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OCKException("Unexpected error during GCM encryption: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] ciphertext,
            int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws OCKException {
        try {
            String cipherAlg = getAESCipherAlgorithm(keyLen, "GCM");
            long cipherId = NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipherAlg);
            try {
                byte[] combinedInput = new byte[cipherLen + tagLen];
                System.arraycopy(ciphertext, cipherOffset, combinedInput, 0, cipherLen);
                System.arraycopy(ciphertext, cipherOffset + cipherLen, combinedInput, cipherLen, tagLen);

                NativeOpenSSLImplementation.GCM_init(getFipsFlag(), cipherId, 0, key, iv, tagLen);
                NativeOpenSSLImplementation.GCM_decryptFinal(getFipsFlag(), cipherId,
                        combinedInput, 0, combinedInput.length, plaintext, plaintextOffset, aad, aadLen, tagLen);
                return 0;
            } finally {
                NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
            }
        } catch (IllegalArgumentException e) {
            throw new OCKException("Invalid GCM decryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OCKException("Unexpected error during GCM decryption: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag,
            int tagLen) throws OCKException {
        try {
            int totalLen = NativeOpenSSLImplementation.GCM_encryptFinal(getFipsFlag(), gcmCtx,
                    input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tagLen);
            int cipherLen = Math.max(0, totalLen - tagLen);
            System.arraycopy(ciphertext, ciphertextOffset + cipherLen, tag, 0, tagLen);
            return cipherLen;
        } catch (Exception e) {
            throw new OCKException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws OCKException {
        try {
            return NativeOpenSSLImplementation.GCM_decryptFinal(getFipsFlag(), gcmCtx,
                    ciphertext, cipherOffset, cipherLen + tagLen, plaintext, plaintextOffset, aad, aadLen, tagLen);
        } catch (Exception e) {
            throw new OCKException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset) throws OCKException {
        try {
            return NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 1,
                    input, inOffset, inLen, ciphertext, ciphertextOffset, null, 0);
        } catch (Exception e) {
            throw new OCKException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) throws OCKException {
        try {
            return NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 0,
                    ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, null, 0);
        } catch (Exception e) {
            throw new OCKException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OCKException {
        try {
            NativeOpenSSLImplementation.GCM_init(getFipsFlag(), gcmCtx, 1, key, iv, DEFAULT_GCM_TAG_LEN);
            if (aad != null && aadLen > 0) {
                NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 1,
                        EMPTY_BYTE_ARRAY, 0, 0, EMPTY_BYTE_ARRAY, 0, aad, aadLen);
            }
            return 0;
        } catch (Exception e) {
            throw new OCKException(e.getMessage(), e);
        }
    }

    @Override
    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) throws OCKException {
        try {
            NativeOpenSSLImplementation.GCM_init(getFipsFlag(), gcmCtx, 0, key, iv, DEFAULT_GCM_TAG_LEN);
            if (aad != null && aadLen > 0) {
                NativeOpenSSLImplementation.GCM_update(getFipsFlag(), gcmCtx, 0,
                        EMPTY_BYTE_ARRAY, 0, 0, EMPTY_BYTE_ARRAY, 0, aad, aadLen);
            }
            return 0;
        } catch (Exception e) {
            throw new OCKException(e.getMessage(), e);
        }
    }

    @Override
    public void do_GCM_delete() throws OCKException {
        // No-op for OpenSSL backend - GCM contexts are managed explicitly by create/free.
    }

    @Override
    public void free_GCM_ctx(long gcmContextId) throws OCKException {
        NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), gcmContextId);
    }

    @Override
    public long create_GCM_context() throws OCKException {
        return NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), "AES-128-GCM");
    }

    // =========================================================================
    // CCM Functions - Not yet implemented
    // =========================================================================

    @Override
    public long do_CCM_checkHardwareCCMSupport() {
        throw new UnsupportedOperationException("do_CCM_checkHardwareCCMSupport not yet implemented in OpenSSL backend");
    }

    @Override
    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        throw new UnsupportedOperationException("do_CCM_encryptFastJNI_WithHardwareSupport not yet implemented in OpenSSL backend");
    }

    @Override
    public int do_CCM_encryptFastJNI(int keyLen, int ivLen, int inLen, int ciphertextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException {
        throw new UnsupportedOperationException("do_CCM_encryptFastJNI not yet implemented in OpenSSL backend");
    }

    @Override
    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) throws OCKException {
        throw new UnsupportedOperationException("do_CCM_decryptFastJNI_WithHardwareSupport not yet implemented in OpenSSL backend");
    }

    @Override
    public int do_CCM_decryptFastJNI(int keyLen, int ivLen, int ciphertextLen, int plaintextLen, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) throws OCKException {
        throw new UnsupportedOperationException("do_CCM_decryptFastJNI not yet implemented in OpenSSL backend");
    }

    /**
     * Determines the AES cipher algorithm name based on key length and mode.
     * Consolidates cipher algorithm mapping to avoid code duplication.
     *
     * @param keyLen The AES key length in bytes (16, 24, or 32)
     * @param mode The cipher mode (e.g., "GCM", "CCM")
     * @return The OpenSSL cipher algorithm name (e.g., "AES-128-GCM")
     * @throws IllegalArgumentException if key length is invalid
     */
    private String getAESCipherAlgorithm(int keyLen, String mode) {
        String keySize;
        switch (keyLen) {
            case 16:
                keySize = "128";
                break;
            case 24:
                keySize = "192";
                break;
            case 32:
                keySize = "256";
                break;
            default:
                throw new IllegalArgumentException("Invalid AES key length: " + keyLen + " (must be 16, 24, or 32 bytes)");
        }
        return "AES-" + keySize + "-" + mode;
    }

    @Override
    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] input,
            int inLen, byte[] ciphertext, int ciphertextLen, int tagLen) throws OCKException {
        try {
            // Determine cipher algorithm based on key length
            String cipherAlg = getAESCipherAlgorithm(keyLen, "CCM");
            
            // Create a cipher context for this operation
            long cipherId = NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipherAlg);
            
            // Initialize CCM cipher for encryption
            NativeOpenSSLImplementation.CCM_init(getFipsFlag(), cipherId, 1, key, iv, tagLen);
            
            // Perform CCM encryption (single-shot operation)
            int outputLen = NativeOpenSSLImplementation.CCM_encryptFinal(
                getFipsFlag(), cipherId, input, 0, inLen, ciphertext, 0, aad, aadLen, tagLen);
            
            // Clean up cipher context
            NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
            
            return 0; // Success
        } catch (IllegalArgumentException e) {
            throw new OCKException("Invalid CCM encryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OCKException("Unexpected error during CCM encryption: " + e.getMessage(), e);
        }
    }

    @Override
    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen,
            byte[] ciphertext, int ciphertextLength, byte[] plaintext, int plaintextLength, int tagLen)
            throws OCKException {
        try {
            // Determine cipher algorithm based on key length
            String cipherAlg = getAESCipherAlgorithm(keyLen, "CCM");
            
            // Create a cipher context for this operation
            long cipherId = NativeOpenSSLImplementation.CIPHER_create(getFipsFlag(), cipherAlg);
            
            // Initialize CCM cipher for decryption
            NativeOpenSSLImplementation.CCM_init(getFipsFlag(), cipherId, 0, key, iv, tagLen);
            
            // Perform CCM decryption (single-shot operation)
            int outputLen = NativeOpenSSLImplementation.CCM_decryptFinal(
                getFipsFlag(), cipherId, ciphertext, 0, ciphertextLength, plaintext, 0, aad, aadLen, tagLen);
            
            // Clean up cipher context
            NativeOpenSSLImplementation.CIPHER_delete(getFipsFlag(), cipherId);
            
            return 0; // Success
        } catch (IllegalArgumentException e) {
            throw new OCKException("Invalid CCM decryption parameters: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OCKException("Unexpected error during CCM decryption: " + e.getMessage(), e);
        }
    }

    @Override
    public void do_CCM_delete() throws OCKException {
        // No-op for OpenSSL backend - contexts are managed per-operation
    }

    // =========================================================================
    // RSA Cipher Functions - Not yet implemented
    // =========================================================================

    @Override
    public int RSACIPHER_public_encrypt(long rsaKeyId, int rsaPaddingId, int mdId, int mgf1Id, byte[] plaintext,
            int plaintextOffset, int plaintextLen, byte[] ciphertext, int ciphertextOffset) throws OCKException {
        throw new UnsupportedOperationException("RSACIPHER_public_encrypt not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSACIPHER_private_encrypt(long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws OCKException {
        throw new UnsupportedOperationException("RSACIPHER_private_encrypt not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSACIPHER_public_decrypt(long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset) throws OCKException {
        throw new UnsupportedOperationException("RSACIPHER_public_decrypt not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSACIPHER_private_decrypt(long rsaKeyId, int rsaPaddingId, int mdId, int mgf1Id, byte[] ciphertext,
            int ciphertextOffset, int ciphertextLen, byte[] plaintext, int plaintextOffset, boolean convertKey)
            throws OCKException {
        throw new UnsupportedOperationException("RSACIPHER_private_decrypt not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // DH Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long DHKEY_generate(int numBits) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_generateParameters(int numBits) {
        throw new UnsupportedOperationException("DHKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_generate(byte[] dhParameters) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_getParameters(long dhKeyId) {
        throw new UnsupportedOperationException("DHKEY_getParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_getPublicKeyBytes(long dhKeyId) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public long DHKEY_createPKey(long dhKeyId) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_createPKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DHKEY_computeDHSecret(long pubKeyId, long privKeyId) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_computeDHSecret not yet implemented in OpenSSL backend");
    }

    @Override
    public void DHKEY_delete(long dhKeyId) throws OCKException {
        throw new UnsupportedOperationException("DHKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // RSA Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long RSAKEY_generate(int numBits, long e) throws OCKException {
        throw new UnsupportedOperationException("RSAKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long RSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("RSAKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long RSAKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("RSAKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("RSAKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("RSAKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSAKEY_size(long rsaKeyId) {
        throw new UnsupportedOperationException("RSAKEY_size not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAKEY_delete(long rsaKeyId) {
        throw new UnsupportedOperationException("RSAKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // DSA Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long DSAKEY_generate(int numBits) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_generateParameters(int numBits) {
        throw new UnsupportedOperationException("DSAKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_generate(byte[] dsaParameters) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_getParameters(long dsaKeyId) {
        throw new UnsupportedOperationException("DSAKEY_getParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public long DSAKEY_createPKey(long dsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_createPKey not yet implemented in OpenSSL backend");
    }

    @Override
    public void DSAKEY_delete(long dsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("DSAKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // PKey Functions - Not yet implemented
    // =========================================================================

    @Override
    public void PKEY_delete(long pkeyId) throws OCKException {
        throw new UnsupportedOperationException("PKEY_delete not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // Digest Functions
    // =========================================================================

    @Override
    public long DIGEST_create(String digestAlgo) throws OCKException {
        return NativeOpenSSLImplementation.DIGEST_create(getFipsFlag(), normalizeDigestAlgorithm(digestAlgo));
    }

    @Override
    public long DIGEST_copy(long digestId) throws OCKException {
        return NativeOpenSSLImplementation.DIGEST_copy(getFipsFlag(), digestId);
    }

    @Override
    public int DIGEST_update(long digestId, byte[] input, int offset, int length) throws OCKException {
        return NativeOpenSSLImplementation.DIGEST_update(getFipsFlag(), digestId, input, offset, length);
    }

    @Override
    public void DIGEST_updateFastJNI(long digestId, long inputBuffer, int length) throws OCKException {
        throw new UnsupportedOperationException("DIGEST_updateFastJNI not supported by OpenSSL backend");
    }

    @Override
    public byte[] DIGEST_digest(long digestId) throws OCKException {
        return NativeOpenSSLImplementation.DIGEST_digest(getFipsFlag(), digestId);
    }

    @Override
    public void DIGEST_digest_and_reset(long digestId, long outputBuffer, int length) throws OCKException {
        throw new UnsupportedOperationException("DIGEST_digest_and_reset(long, long, int) not supported by OpenSSL backend");
    }

    @Override
    public int DIGEST_digest_and_reset(long digestId, byte[] output) throws OCKException {
        return NativeOpenSSLImplementation.DIGEST_digest_and_reset(getFipsFlag(), digestId, output, 0);
    }

    @Override
    public int DIGEST_size(long digestId) throws OCKException {
        return NativeOpenSSLImplementation.DIGEST_size(getFipsFlag(), digestId);
    }

    @Override
    public void DIGEST_reset(long digestId) throws OCKException {
        NativeOpenSSLImplementation.DIGEST_reset(getFipsFlag(), digestId);
    }

    @Override
    public void DIGEST_delete(long digestId) throws OCKException {
        NativeOpenSSLImplementation.DIGEST_delete(getFipsFlag(), digestId);
    }

    @Override
    public int DIGEST_PKCS12KeyDeriveHelp(long digestId, byte[] input, int offset, int length, int iterationCount)
            throws OCKException {
        throw new UnsupportedOperationException("DIGEST_PKCS12KeyDeriveHelp not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public byte[] SIGNATURE_sign(long digestId, long pkeyId, boolean convert) throws OCKException {
        throw new UnsupportedOperationException("SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean SIGNATURE_verify(long digestId, long pkeyId, byte[] sigBytes) throws OCKException {
        throw new UnsupportedOperationException("SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId, byte[] bytes) throws OCKException {
        throw new UnsupportedOperationException("SIGNATUREEdDSA_signOneShot not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId, byte[] sigBytes, byte[] oneShot) throws OCKException {
        throw new UnsupportedOperationException("SIGNATUREEdDSA_verifyOneShot not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // RSA PSS Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public int RSAPSS_signInit(long rsaPssId, long pkeyId, int saltlen, boolean convert) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_signInit not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSAPSS_verifyInit(long rsaPssId, long pkeyId, int saltlen) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_verifyInit not yet implemented in OpenSSL backend");
    }

    @Override
    public int RSAPSS_getSigLen(long rsaPssId) {
        throw new UnsupportedOperationException("RSAPSS_getSigLen not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_signFinal(long rsaPssId, byte[] signature, int length) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_signFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean RSAPSS_verifyFinal(long rsaPssId, byte[] sigBytes, int length) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_verifyFinal not yet implemented in OpenSSL backend");
    }

    @Override
    public long RSAPSS_createContext(String digestAlgo, String mgf1SpecAlgo) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_createContext not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_releaseContext(long rsaPssId) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_releaseContext not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_digestUpdate(long rsaPssId, byte[] input, int offset, int length) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_digestUpdate not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_reset(long digestId) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_reset not yet implemented in OpenSSL backend");
    }

    @Override
    public void RSAPSS_resetDigest(long rsaPssId) throws OCKException {
        throw new UnsupportedOperationException("RSAPSS_resetDigest not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // DSA Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public byte[] DSANONE_SIGNATURE_sign(byte[] digest, long dsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("DSANONE_SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean DSANONE_SIGNATURE_verify(byte[] digest, long dsaKeyId, byte[] sigBytes) throws OCKException {
        throw new UnsupportedOperationException("DSANONE_SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // RSASSL Signature Functions - Not yet implemented
    // =========================================================================

    @Override
    public byte[] RSASSL_SIGNATURE_sign(byte[] digest, long rsaKeyId) throws OCKException {
        throw new UnsupportedOperationException("RSASSL_SIGNATURE_sign not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean RSASSL_SIGNATURE_verify(byte[] digest, long rsaKeyId, byte[] sigBytes, boolean convert)
            throws OCKException {
        throw new UnsupportedOperationException("RSASSL_SIGNATURE_verify not yet implemented in OpenSSL backend");
    }

    // =========================================================================
    // HMAC Functions
    // =========================================================================

    @Override
    public long HMAC_create(String digestAlgo) throws OCKException {
        return NativeOpenSSLImplementation.HMAC_create(getFipsFlag(), normalizeDigestAlgorithm(digestAlgo));
    }

    @Override
    public int HMAC_update(long hmacId, byte[] key, int keyLength, byte[] input, int inputOffset, int inputLength,
            boolean needInit) throws OCKException {
        if (needInit) {
            NativeOpenSSLImplementation.HMAC_init(getFipsFlag(), hmacId, key, keyLength);
        }
        return NativeOpenSSLImplementation.HMAC_update(getFipsFlag(), hmacId, input, inputOffset, inputLength);
    }

    @Override
    public int HMAC_doFinal(long hmacId, byte[] key, int keyLength, byte[] hmac, boolean needInit)
            throws OCKException {
        if (needInit) {
            NativeOpenSSLImplementation.HMAC_init(getFipsFlag(), hmacId, key, keyLength);
        }
        return NativeOpenSSLImplementation.HMAC_doFinal(getFipsFlag(), hmacId, hmac, 0);
    }

    @Override
    public int HMAC_size(long hmacId) throws OCKException {
        return NativeOpenSSLImplementation.HMAC_size(getFipsFlag(), hmacId);
    }

    @Override
    public void HMAC_delete(long hmacId) throws OCKException {
        NativeOpenSSLImplementation.HMAC_delete(getFipsFlag(), hmacId);
    }

    // =========================================================================
    // EC Key Functions - Not yet implemented
    // =========================================================================

    @Override
    public long ECKEY_generate(int numBits) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_generate(String curveOid) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long XECKEY_generate(int option, long bufferPtr) throws OCKException {
        throw new UnsupportedOperationException("XECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_generateParameters(int numBits) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_generateParameters(String curveOid) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_generateParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_generate(byte[] ecParameters) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_generate not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_createPrivateKey(byte[] privateKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long XECKEY_createPrivateKey(byte[] privateKeyBytes, long bufferPtr) throws OCKException {
        throw new UnsupportedOperationException("XECKEY_createPrivateKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_createPublicKey(byte[] publicKeyBytes, byte[] parameterBytes) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public long XECKEY_createPublicKey(byte[] publicKeyBytes) throws OCKException {
        throw new UnsupportedOperationException("XECKEY_createPublicKey not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_getParameters(long ecKeyId) {
        throw new UnsupportedOperationException("ECKEY_getParameters not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId) throws OCKException {
        throw new UnsupportedOperationException("XECKEY_getPrivateKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_getPublicKeyBytes(long ecKeyId) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] XECKEY_getPublicKeyBytes(long xecKeyId) throws OCKException {
        throw new UnsupportedOperationException("XECKEY_getPublicKeyBytes not yet implemented in OpenSSL backend");
    }

    @Override
    public long ECKEY_createPKey(long ecKeyId) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_createPKey not yet implemented in OpenSSL backend");
    }

    @Override
    public void ECKEY_delete(long ecKeyId) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_delete not yet implemented in OpenSSL backend");
    }

    @Override
    public void XECKEY_delete(long xecKeyId) throws OCKException {
        throw new UnsupportedOperationException("XECKEY_delete not yet implemented in OpenSSL backend");
    }

    @Override
    public long XDHKeyAgreement_init(long privId) {
        throw new UnsupportedOperationException("XDHKeyAgreement_init not yet implemented in OpenSSL backend");
    }

    @Override
    public void XDHKeyAgreement_setPeer(long genCtx, long pubId) {
        throw new UnsupportedOperationException("XDHKeyAgreement_setPeer not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_computeECDHSecret(long pubEcKeyId, long privEcKeyId) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_computeECDHSecret not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] XECKEY_computeECDHSecret(long genCtx, long pubEcKeyId, long privEcKeyId, int secrectBufferSize)
            throws OCKException {
        throw new UnsupportedOperationException("XECKEY_computeECDHSecret not yet implemented in OpenSSL backend");
    }

    @Override
    public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes, int digestBytesLen, long ecPrivateKeyId)
            throws OCKException {
        throw new UnsupportedOperationException("ECKEY_signDatawithECDSA not yet implemented in OpenSSL backend");
    }

    @Override
    public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes, int digestBytesLen, byte[] sigBytes, int sigBytesLen,
            long ecPublicKeyId) throws OCKException {
        throw new UnsupportedOperationException("ECKEY_verifyDatawithECDSA not yet implemented in OpenSSL backend");
    }

    // Note: Additional methods from NativeInterface that are not yet implemented
    // will throw UnsupportedOperationException. These can be added as needed.
}


