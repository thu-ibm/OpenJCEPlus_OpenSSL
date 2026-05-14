/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLSignature.h
 * @brief Digital signature operations using OpenSSL.
 *
 * This header defines the interface for digital signature operations.
 * It supports various signature algorithms including:
 * - RSA with SHA-1, SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512)
 * - RSA with SHA-3 family (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
 * - RSA-PSS (Probabilistic Signature Scheme)
 * - ECDSA with various hash algorithms
 * - EdDSA (Ed25519, Ed448)
 * - DSA with various hash algorithms
 *
 * The implementation uses OpenSSL's EVP interface for algorithm-independent
 * signature operations with support for both signing and verification.
 */

#ifndef _OPENSSL_SIGNATURE_H
#define _OPENSSL_SIGNATURE_H

#include <jni.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include "OpenSSLContext.h"

/**
 * Signature operation modes
 */
#define SIGNATURE_MODE_SIGN   1
#define SIGNATURE_MODE_VERIFY 2

/**
 * Structure to hold OpenSSL signature context information.
 * This structure maintains the state for signature operations.
 */
typedef struct {
    EVP_MD_CTX*       mdCtx;        // OpenSSL message digest context for signing/verification
    EVP_PKEY*         pkey;         // Public or private key
    const EVP_MD*     md;           // Message digest algorithm (NULL for EdDSA)
    int               mode;         // SIGNATURE_MODE_SIGN or SIGNATURE_MODE_VERIFY
    int               signatureSize; // Expected signature size in bytes
    EVP_PKEY_CTX*     pkeyCtx;      // Key context for PSS parameters
    int               isEdDSA;      // Flag: 1 if EdDSA (Ed25519/Ed448), 0 otherwise
    unsigned char*    dataBuffer;   // Buffer for EdDSA data accumulation
    size_t            dataBufferSize; // Current size of buffered data
    size_t            dataBufferCapacity; // Allocated capacity of buffer
} OpenSSLSignatureContext;

/**
 * Create a new signature context for the specified algorithm and key.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag (1 for FIPS, 0 for non-FIPS)
 * @param keyBytes Encoded key bytes (PKCS#8 for private, X.509 for public)
 * @param keyLength Length of key bytes
 * @param algorithm Signature algorithm name (e.g., "SHA256withRSA", "SHA512withECDSA")
 * @param mode 0 for signing (private key), 1 for verification (public key)
 * @return Signature context ID (pointer cast to jlong), or 0 on failure
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1create(
    JNIEnv* env, jclass cls, jint fipsFlag, jbyteArray keyBytes,
    jint keyLength, jstring algorithm, jint mode);

/**
 * Update the signature with data to be signed or verified.
 * Can be called multiple times to process data in chunks.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID
 * @param data Input data to sign/verify
 * @param offset Offset in the data array
 * @param dataLen Length of data to process
 * @return 1 on success, negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1update(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId, 
    jbyteArray data, jint offset, jint dataLen);

/**
 * Finalize the signature operation and return the signature bytes.
 * Only valid for signing operations (private key).
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID
 * @return Byte array containing the signature
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1sign(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId);

/**
 * Verify a signature against the accumulated data.
 * Only valid for verification operations (public key).
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID
 * @param signature Signature bytes to verify
 * @return 1 if signature is valid, 0 if invalid, negative on error
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1verify(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId, 
    jbyteArray signature);

/**
 * Get the expected signature size in bytes.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID
 * @return Size of signature in bytes, or negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1size(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId);

/**
 * Reset the signature context to its initial state.
 * Allows reusing the same context for a new signature operation.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1reset(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId);

/**
 * Set RSA-PSS parameters for PSS signature operations.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID
 * @param saltLen Salt length in bytes (-1 for digest length, -2 for max)
 * @param mgf1Digest MGF1 digest algorithm name
 * @return 1 on success, negative error code on failure
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1setPSSParams(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId, 
    jint saltLen, jstring mgf1Digest);

/**
 * Delete the signature context and free associated resources.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID to delete
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_SIGNATURE_1delete(
    JNIEnv* env, jclass cls, jint fipsFlag, jlong signatureId);

/**
 * Internal helper function to validate signature context.
 * Centralizes validation logic used by all signature operations.
 *
 * @param env JNI environment
 * @param fipsFlag FIPS mode flag
 * @param signatureId Signature context ID
 * @param functionName Name of calling function (for logging)
 * @param signatureCtx Output parameter for validated signature context
 * @return 1 if valid, 0 if invalid (exception thrown)
 */
int validateSignatureContext(JNIEnv* env, jint fipsFlag, jlong signatureId,
                              const char* functionName,
                              OpenSSLSignatureContext** signatureCtx);

#endif


