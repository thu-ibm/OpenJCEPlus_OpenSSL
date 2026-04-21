/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLJNI.c
 * @brief JNI entry point and context lifecycle management for OpenSSL
 * integration.
 *
 * This file implements the JNI boundary layer for the OpenSSL native bridge,
 * providing the interface between Java (NativeOpenSSLImplementation) and the
 * native OpenSSL C code. Key responsibilities include:
 * - JNI_OnLoad for library initialization
 * - Context creation and destruction (initializeOpenSSL/cleanupOpenSSL)
 * - Context map management for tracking active contexts
 * - Context value queries (CTX_getValue)
 * - ByteBuffer pointer access for direct memory operations
 *
 * The implementation maintains a context map to track active OpenSSL
 * contexts and ensures proper resource cleanup on library unload.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "OpenSSLJNI.h"
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

// Forward declarations
static void initializeDebug(void);

static void initializeDebug(void) {
    static int initialized = 0;

    if (!initialized) {
        char* debugEnv = getenv("OPENSSL_DEBUG");
        if (debugEnv != NULL &&
            (strcmp(debugEnv, "1") == 0 || strcmp(debugEnv, "true") == 0)) {
            debug = 1;
        }
        initialized = 1;
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    // Verify OpenSSL version - require 3.0.0 or later
    // OpenSSL 3.0.0 = 0x30000000L
    unsigned long opensslVersion = OpenSSL_version_num();
    if (opensslVersion < 0x30000000L) {
        fprintf(stderr,
                "[OpenSSL JNI] ERROR: OpenSSL 3.0.0 or later is required.\n");
        fprintf(stderr,
                "[OpenSSL JNI] Current version: %s (0x%08lx)\n",
                OpenSSL_version(OPENSSL_VERSION), opensslVersion);
        fprintf(stderr,
                "[OpenSSL JNI] This library uses OpenSSL 3.0+ APIs "
                "(EVP_MD_fetch, OSSL_LIB_CTX, etc.) which are not available "
                "in older versions.\n");
        fflush(stderr);
        return JNI_ERR;  // Fail library load
    }

    char* debugEnv = getenv("OPENSSL_DEBUG");
    if (debugEnv != NULL &&
        (strcmp(debugEnv, "1") == 0 || strcmp(debugEnv, "true") == 0)) {
        debug = 1;
        fprintf(stderr,
                "[OpenSSL JNI] Debug logging ENABLED (OPENSSL_DEBUG=%s)\n",
                debugEnv);
        fflush(stderr);
    } else {
        fprintf(stderr,
                "[OpenSSL JNI] Debug logging DISABLED (set OPENSSL_DEBUG=1 to "
                "enable)\n");
        fflush(stderr);
    }

    fprintf(stderr, "[OpenSSL JNI] Loaded with OpenSSL version: %s\n",
            OpenSSL_version(OPENSSL_VERSION));
    fflush(stderr);

    return JNI_VERSION_1_8;
}

//============================================================================
// JNI Method Implementations
//============================================================================

/**
 * Initialize OpenSSL - Returns a context ID for compatibility with Java layer.
 *
 * NOTE: This function exists for API compatibility but doesn't actually create
 * a context. The real context management is handled by getOrCreateContext() in
 * OpenSSLUtils.c, which creates singleton contexts per FIPS mode.
 *
 * The returned ID is just a marker (1 for non-FIPS, 2 for FIPS) that matches
 * the singleton context IDs used internally.
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_initializeOpenSSL(
    JNIEnv* env, jclass cls, jboolean isFIPS) {
    static const char* functionName =
        "NativeOpenSSLImplementation.initializeOpenSSL";

    // Initialize debug flag
    initializeDebug();

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    // Trigger context creation through the singleton system
    // This ensures the context is properly initialized
    OpenSSLContext* context = getOrCreateContext(env, isFIPS ? 1 : 0);
    if (context == NULL) {
        logFunctionExit(functionName);
        return -1;
    }

#ifdef DEBUG_OPENSSL_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_OPENSSL OpenSSL initialized with context ID %ld, FIPS "
            "mode: %d",
            context->id, isFIPS);
    }
#endif

    logFunctionExit(functionName);
    return context->id;
}

/**
 * Cleanup OpenSSL - No-op for compatibility.
 *
 * NOTE: Actual cleanup happens automatically via the destructor in
 * OpenSSLUtils.c. Singleton contexts are cleaned up when the library is
 * unloaded.
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_cleanupOpenSSL(
    JNIEnv* env, jclass cls, jlong contextId) {
    static const char* functionName =
        "NativeOpenSSLImplementation.cleanupOpenSSL";

    if (debug) {
        gslogFunctionEntry(functionName);
        gslogMessage(
            "DETAIL_OPENSSL cleanupOpenSSL called for context %ld (no-op, "
            "cleanup handled by destructor)",
            contextId);
        gslogFunctionExit(functionName);
    }

    // No-op: Singleton contexts are managed by OpenSSLUtils.c and cleaned up
    // automatically when the library is unloaded via the destructor.
}

/**
 * Get context value - Returns OpenSSL version or install path.
 *
 * NOTE: contextId is ignored since we use singleton contexts.
 * The information returned is global to the OpenSSL installation.
 */
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CTX_1getValue(
    JNIEnv* env, jclass cls, jlong contextId, jint valueId) {
    static const char* functionName =
        "NativeOpenSSLImplementation.CTX_getValue";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    jstring result = NULL;

    switch (valueId) {
        case VALUE_FIPS_APPROVED_MODE:
            // FIPS mode is determined by the fipsFlag parameter passed to each
            // operation Context ID 2 indicates FIPS mode was requested during
            // initialization
            result =
                (*env)->NewStringUTF(env, (contextId == 2) ? "true" : "false");
            break;

        case VALUE_OPENSSL_VERSION:
            result =
                (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_VERSION));
            break;

        case VALUE_OPENSSL_INSTALL_PATH:
            result = (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_DIR));
            break;

        default:
            setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid value ID");
            break;
    }

    logFunctionExit(functionName);
    return result;
}

//============================================================================
// getByteBufferPointer - Get native pointer from direct ByteBuffer
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_getByteBufferPointer(
    JNIEnv* env, jclass cls, jobject buffer) {
    static const char* functionName =
        "NativeOpenSSLImplementation.getByteBufferPointer";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    void* ptr = (*env)->GetDirectBufferAddress(env, buffer);

    logFunctionExit(functionName);
    return (jlong)ptr;
}
