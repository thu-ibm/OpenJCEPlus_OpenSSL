/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLJNI.h
 * @brief JNI entry point declarations for OpenSSL context management.
 *
 * This header declares the JNI boundary functions that bridge Java
 * (NativeOpenSSLImplementation) to native OpenSSL C code. It provides
 * the interface for:
 * - Context creation and destruction
 * - Context lookup and management
 * - ByteBuffer pointer access
 *
 * This is the primary JNI interface layer - all Java native method calls
 * enter through functions declared in this header.
 */

#ifndef _OPENSSL_JNI_H
#define _OPENSSL_JNI_H

#include <jni.h>

#include "OpenSSLContext.h"

/**
 * NOTE: Context management is handled by getOrCreateContext() in OpenSSLUtils.c
 * which maintains singleton contexts for FIPS and non-FIPS modes.
 *
 * The initializeOpenSSL() and cleanupOpenSSL() functions exist for API
 * compatibility with the Java layer but delegate to the singleton system.
 */

#endif
