# OpenSSL Native Bridge Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Component Details](#component-details)
4. [Data Flows](#data-flows)
5. [Implementation Patterns](#implementation-patterns)
6. [Error Handling](#error-handling)
7. [Memory Management](#memory-management)

---

## Overview

The OpenSSL Native Bridge provides a JNI (Java Native Interface) layer that allows Java cryptographic operations to leverage OpenSSL's high-performance native implementations. This architecture enables:

- **FIPS Mode Support**: Separate contexts for FIPS and non-FIPS operations
- **High Performance**: Direct native OpenSSL calls without Java overhead
- **Multiple Algorithms**: Support for symmetric ciphers, digests, HMAC, KDFs, and authenticated encryption
- **Thread Safety**: Singleton context management with thread-safe initialization

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Java Application Layer                    │
│  (JCE Provider API - javax.crypto.*, java.security.*)       │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Java Provider Implementation                    │
│  - AESGCMCipher, MessageDigest implementations, etc.        │
│  - OpenSSLContext (Java wrapper)                            │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│          NativeOpenSSLImplementation (JNI Bridge)           │
│  - Native method declarations                                │
│  - Library loading logic                                     │
└────────────────────────┬────────────────────────────────────┘
                         │ JNI Boundary
┌────────────────────────▼────────────────────────────────────┐
│                  Native C Layer (JNI)                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ OpenSSLJNI.c - Entry point & context lifecycle       │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ OpenSSLUtils.c - Context management & utilities      │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ OpenSSLHelpers.c - Common helper functions           │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Algorithm Implementations:                            │  │
│  │ - OpenSSLDigest.c (SHA-1, SHA-2, SHA-3)             │  │
│  │ - OpenSSLHMAC.c (HMAC operations)                    │  │
│  │ - OpenSSLSymmetricCipher.c (AES, DES, ChaCha20)     │  │
│  │ - OpenSSLGCM.c (AES-GCM authenticated encryption)    │  │
│  │ - OpenSSLCCM.c (AES-CCM authenticated encryption)    │  │
│  │ - OpenSSLHKDF.c (HKDF key derivation)               │  │
│  │ - OpenSSLPBKDF2.c (PBKDF2 key derivation)           │  │
│  │ - OpenSSLKeyWrap.c (AES Key Wrap RFC 3394/5649)     │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                    OpenSSL 3.x Library                       │
│  - EVP API (high-level cryptographic operations)            │
│  - Provider architecture (FIPS, default, base)              │
│  - Low-level algorithm implementations                       │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
src/main/
├── java/com/ibm/crypto/plus/provider/
│   ├── openssl/
│   │   ├── NativeOpenSSLImplementation.java  # JNI method declarations
│   │   └── OpenSSLContext.java               # Java context wrapper
│   ├── AESGCMCipher.java                     # GCM cipher implementation
│   └── base/
│       └── GCMCipher.java                    # Base GCM cipher class
└── native/openssl/
    ├── OpenSSLJNI.c                          # JNI entry point
    ├── OpenSSLUtils.c                        # Core utilities
    ├── OpenSSLHelpers.c                      # Helper functions
    ├── OpenSSLContext.h                      # Context structures
    ├── OpenSSLExceptionCodes.h               # Error codes
    ├── OpenSSLLogging.h                      # Logging infrastructure
    ├── OpenSSLDigest.c/h                     # Message digest operations
    ├── OpenSSLHMAC.c/h                       # HMAC operations
    ├── OpenSSLSymmetricCipher.c/h            # Symmetric encryption
    ├── OpenSSLGCM.c/h                        # GCM mode
    ├── OpenSSLCCM.c/h                        # CCM mode
    ├── OpenSSLHKDF.c/h                       # HKDF key derivation
    ├── OpenSSLPBKDF2.c/h                     # PBKDF2 key derivation
    └── OpenSSLKeyWrap.c/h                    # AES Key Wrap
```

---

## Component Details

### 1. Library Loading (NativeOpenSSLImplementation.java)

**Purpose**: Manages the loading of OpenSSL and JNI bridge libraries.

**Key Features**:
- Environment variable support (`OPENSSL_HOME`, `OPENSSL_DEBUG`)
- System property overrides (`openssl.library.path`, `jgskit.library.path`)
- Platform-specific path resolution (Windows vs Unix)
- Dependency order: OpenSSL libraries → JNI bridge library

**Loading Sequence**:
```
1. Static initializer runs
2. preloadOpenSSL() → loads libssl-3-x64 and libcrypto-3-x64
3. preloadJGskit() → loads jgskit_openssl (JNI bridge)
4. JNI_OnLoad() called in native code
5. Debug logging initialized
```

### 2. Context Management (OpenSSLUtils.c)

**Purpose**: Manages OpenSSL library contexts with FIPS mode support.

**Key Structures**:
```c
typedef struct {
    long id;                    // Context ID (1=non-FIPS, 2=FIPS)
    OSSL_LIB_CTX* libctx;      // OpenSSL library context
    OSSL_PROVIDER* fips;        // FIPS provider (FIPS mode only)
    OSSL_PROVIDER* base;        // Base provider (FIPS mode only)
    OSSL_PROVIDER* defaultProv; // Default provider (non-FIPS only)
} OpenSSLContext;
```

**Context Lifecycle**:
```
┌─────────────────────────────────────────────────────────┐
│ 1. First Operation Request                              │
│    - Java calls initializeOpenSSL(isFIPS)              │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│ 2. getOrCreateContext(env, isFIPS)                     │
│    - Acquire write lock (thread-safe)                  │
│    - Check if context exists                           │
│    - If not, call createContext()                      │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│ 3. createContext(env, isFIPS)                          │
│    IF FIPS:                                            │
│      - Create OSSL_LIB_CTX                            │
│      - Load FIPS provider                             │
│      - Enable FIPS properties                         │
│      - Load base provider                             │
│    ELSE:                                               │
│      - Create OSSL_LIB_CTX                            │
│      - Load default provider                          │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│ 4. Store in global singleton                           │
│    - fipsContext or nonFipsContext                     │
│    - Release lock                                       │
│    - Return context                                     │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│ 5. Subsequent Operations                                │
│    - Reuse existing context (no recreation)            │
│    - Thread-safe access via lock                       │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│ 6. Library Unload                                       │
│    - cleanupContexts() called (destructor)             │
│    - Unload providers                                   │
│    - Free OSSL_LIB_CTX                                 │
│    - Free context structures                            │
└─────────────────────────────────────────────────────────┘
```

### 3. Helper Functions (OpenSSLHelpers.c)

**Purpose**: Provides reusable utility functions for common operations.

**Categories**:

#### Logging Helpers
```c
void logFunctionEntry(const char* functionName);
void logFunctionExit(const char* functionName);
```

#### Context Validation
```c
int validateAndGetContext(JNIEnv* env, jint fipsFlag,
                         const char* functionName,
                         OpenSSLContext** outContext);
```

#### String Handling
```c
const char* getStringUTFCharsSafe(JNIEnv* env, jstring javaString,
                                  const char* functionName,
                                  const char* errorMsg);
void cleanupStringUTFChars(JNIEnv* env, jstring javaString, const char* str);
```

#### Byte Array Handling
```c
jbyte* getByteArrayElementsSafe(JNIEnv* env, jbyteArray array,
                                const char* functionName,
                                const char* errorMsg);
void cleanupByteArray(JNIEnv* env, jbyteArray array,
                     jbyte* bytes, jint mode);
void cleanupIOArrays(JNIEnv* env,
                    jbyteArray inputArray, jbyte* inputBytes,
                    jbyteArray outputArray, jbyte* outputBytes,
                    jboolean commitOutput);
```

#### Validation Helpers
```c
int validateIntRange(JNIEnv* env, jint value, jint min, jint max,
                    const char* functionName, const char* errorMsg);
int validateArrayLength(JNIEnv* env, jbyteArray array, jint min, jint max,
                       const char* functionName, const char* errorMsg);
int validateOffsetAndLength(JNIEnv* env, jint arrayLength,
                           jint offset, jint length,
                           const char* functionName,
                           const char* errorMsg);
```

#### OpenSSL Object Helpers
```c
const EVP_MD* fetchDigestSafe(JNIEnv* env, OpenSSLContext* context,
                              const char* algoName, const char* functionName,
                              int errorCode, const char* errorMsg);
EVP_CIPHER_CTX* createCipherCtxSafe(JNIEnv* env, const char* functionName,
                                    int errorCode, const char* errorMsg);
```

---

## Data Flows

### 1. Message Digest Flow (SHA-256 Example)

```
┌─────────────────────────────────────────────────────────────┐
│ Java Application                                             │
│   MessageDigest md = MessageDigest.getInstance("SHA-256")   │
│   md.update(data)                                           │
│   byte[] hash = md.digest()                                 │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ Java Provider (OpenJCEPlus)                                 │
│   OpenSSLDigest extends MessageDigestSpi                    │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ NativeOpenSSLImplementation.java                            │
│   native long DIGEST_create(int fipsFlag, String algo)     │
│   native int DIGEST_update(long id, byte[] data, ...)      │
│   native byte[] DIGEST_digest(long id)                     │
└────────────────┬────────────────────────────────────────────┘
                 │ JNI Boundary
┌────────────────▼────────────────────────────────────────────┐
│ OpenSSLDigest.c                                             │
│                                                              │
│ DIGEST_create:                                              │
│   1. logFunctionEntry()                                     │
│   2. validateAndGetContext() → get OpenSSL context         │
│   3. getStringUTFCharsSafe() → get algorithm name          │
│   4. mallocSafe() → allocate OpenSSLDigestContext          │
│   5. fetchDigestSafe() → EVP_MD_fetch(libctx, "SHA-256")  │
│   6. createMDCtxSafe() → EVP_MD_CTX_new()                 │
│   7. EVP_DigestInit_ex2() → initialize digest              │
│   8. logFunctionExit()                                      │
│   9. return (jlong)digestCtx                                │
│                                                              │
│ DIGEST_update:                                              │
│   1. logFunctionEntry()                                     │
│   2. validateDigestContext() → validate context ID         │
│   3. getByteArrayElementsSafe() → get data bytes           │
│   4. EVP_DigestUpdate(mdCtx, data, length)                 │
│   5. cleanupByteArray() → release JNI array                │
│   6. logFunctionExit()                                      │
│   7. return 1 (success)                                     │
│                                                              │
│ DIGEST_digest:                                              │
│   1. logFunctionEntry()                                     │
│   2. validateDigestContext() → validate context ID         │
│   3. newByteArraySafe() → allocate output array            │
│   4. getByteArrayElementsSafe() → get output buffer        │
│   5. EVP_DigestFinal_ex(mdCtx, buffer, &len)              │
│   6. cleanupByteArray() → commit output                    │
│   7. EVP_DigestInit_ex2() → reset for reuse               │
│   8. logFunctionExit()                                      │
│   9. return output array                                    │
└─────────────────────────────────────────────────────────────┘
```

### 2. AES-GCM Encryption Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Java Application                                             │
│   Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding")  │
│   cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)           │
│   cipher.updateAAD(aad)                                     │
│   byte[] ciphertext = cipher.doFinal(plaintext)            │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ AESGCMCipher.java extends GCMCipher                         │
│   - Manages GCM parameters (IV, tag length, AAD)           │
│   - Calls native methods                                    │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ NativeOpenSSLImplementation.java                            │
│   native long CIPHER_create(int fips, String name)         │
│   native void GCM_init(long id, int encrypt, ...)          │
│   native int GCM_update(long id, byte[] in, ...)           │
│   native int GCM_encryptFinal(long id, ...)                │
└────────────────┬────────────────────────────────────────────┘
                 │ JNI Boundary
┌────────────────▼────────────────────────────────────────────┐
│ OpenSSLSymmetricCipher.c + OpenSSLGCM.c                    │
│                                                              │
│ CIPHER_create("AES-256-GCM"):                              │
│   1. validateAndGetContext()                                │
│   2. mallocSafe() → allocate CipherContext                 │
│   3. createCipherCtxSafe() → EVP_CIPHER_CTX_new()         │
│   4. EVP_CIPHER_fetch(libctx, "AES-256-GCM")              │
│   5. return (jlong)cipherCtx                                │
│                                                              │
│ GCM_init:                                                   │
│   1. validateCipherContext()                                │
│   2. getByteArrayElementsSafe() → get key, IV              │
│   3. EVP_CipherInit_ex(ctx, cipher, NULL, NULL, encrypt)   │
│   4. EVP_CIPHER_CTX_ctrl(SET_IVLEN) if non-default        │
│   5. EVP_CipherInit_ex(ctx, NULL, NULL, key, IV, encrypt)  │
│   6. Store tagLen in context                                │
│   7. cleanupByteArrays()                                    │
│                                                              │
│ GCM_update (with AAD):                                      │
│   1. validateCipherContext()                                │
│   2. Process AAD: EVP_CipherUpdate(ctx, NULL, &len, aad)  │
│   3. Process plaintext: EVP_CipherUpdate(ctx, out, in)     │
│   4. return output length                                   │
│                                                              │
│ GCM_encryptFinal:                                           │
│   1. validateCipherContext()                                │
│   2. Process final AAD if present                          │
│   3. validateOutputBuffer() → check output size            │
│   4. Process final input if present                        │
│   5. EVP_CipherFinal_ex() → finalize                       │
│   6. EVP_CIPHER_CTX_ctrl(GET_TAG) → get auth tag          │
│   7. Append tag to output                                   │
│   8. return total length (ciphertext + tag)                │
└─────────────────────────────────────────────────────────────┘
```

### 3. HKDF Key Derivation Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Java Application                                             │
│   SecretKeyFactory factory =                                │
│     SecretKeyFactory.getInstance("HKDF-SHA256")            │
│   SecretKey derived = factory.generateSecret(spec)         │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ NativeOpenSSLImplementation.java                            │
│   native byte[] HKDF_extract(int fips, String algo,        │
│                              byte[] salt, byte[] ikm)       │
│   native byte[] HKDF_expand(int fips, String algo,         │
│                             byte[] prk, byte[] info, int len)│
│   native byte[] HKDF_derive(int fips, String algo,         │
│                             byte[] salt, byte[] ikm,        │
│                             byte[] info, int len)           │
└────────────────┬────────────────────────────────────────────┘
                 │ JNI Boundary
┌────────────────▼────────────────────────────────────────────┐
│ OpenSSLHKDF.c                                               │
│                                                              │
│ HKDF_derive (combined extract + expand):                   │
│   1. logFunctionEntry()                                     │
│   2. validateAndGetContext()                                │
│   3. getStringUTFCharsSafe() → get algorithm name          │
│   4. getByteArrayElementsSafe() → get salt, IKM, info      │
│   5. mallocSafe() → allocate output buffer                 │
│   6. EVP_MD_fetch(libctx, algo)                            │
│   7. fetchKDFSafe() → EVP_KDF_fetch(libctx, "HKDF")       │
│   8. EVP_KDF_CTX_new(kdf)                                  │
│   9. Build OSSL_PARAM array:                               │
│      - MODE = EXTRACT_AND_EXPAND                           │
│      - DIGEST = algorithm name                             │
│      - KEY = IKM                                           │
│      - SALT = salt (if present)                            │
│      - INFO = info (if present)                            │
│  10. EVP_KDF_derive(kctx, output, length, params)         │
│  11. Cleanup contexts and arrays                           │
│  12. newByteArraySafe() → create result array              │
│  13. SetByteArrayRegion() → copy output                    │
│  14. logFunctionExit()                                      │
│  15. return result array                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation Patterns

### 1. Standard Function Pattern

Every JNI function follows this pattern:

```c
JNIEXPORT returnType JNICALL
Java_package_Class_methodName(JNIEnv* env, jclass cls, parameters) {
    static const char* functionName = "Class.methodName";
    
    // 1. Entry logging
    logFunctionEntry(functionName);
    
    // 2. Context validation
    Context* ctx = NULL;
    if (!validateContext(env, fipsFlag, id, functionName, &ctx)) {
        return errorValue;
    }
    
    // 3. Parameter validation and extraction
    jbyte* bytes = getByteArrayElementsSafe(env, array, functionName, "error");
    if (bytes == NULL) {
        return errorValue;
    }
    
    // 4. OpenSSL operations
    int result = EVP_SomeOperation(ctx, bytes, length);
    
    // 5. Cleanup (AFTER operation, BEFORE error check)
    cleanupByteArray(env, array, bytes, JNI_ABORT);
    
    // 6. Error handling
    if (result != 1) {
        throwOpenSSLException(env, ERROR_CODE, "Operation failed");
        logOpenSSLError("EVP_SomeOperation");
        logFunctionExit(functionName);
        return errorValue;
    }
    
    // 7. Exit logging and return
    logFunctionExit(functionName);
    return successValue;
}
```

### 2. Resource Management Pattern

**Allocation Order**:
1. Validate inputs
2. Allocate native resources
3. Perform operations
4. Cleanup in reverse order

**Cleanup Rules**:
- Always cleanup after operations, not before error checks
- Use `JNI_ABORT` for input arrays (no copy back)
- Use `0` or `JNI_TRUE` for output arrays (copy back)
- Free native memory with `free()`
- Free OpenSSL objects with appropriate `_free()` functions

**Example**:
```c
// Allocate
jbyte* input = getByteArrayElementsSafe(env, inputArray, ...);
jbyte* output = getByteArrayElementsSafe(env, outputArray, ...);
unsigned char* buffer = mallocSafe(env, size, ...);

// Operate
int result = EVP_Operation(ctx, output, input, buffer, size);

// Cleanup (reverse order, after operation)
free(buffer);
cleanupByteArray(env, outputArray, output, JNI_TRUE);  // Commit
cleanupByteArray(env, inputArray, input, JNI_ABORT);   // Discard

// Check result
if (result != 1) {
    // Handle error
}
```

### 3. Error Handling Pattern

**Three-Level Error Handling**:

1. **JNI Exceptions** (Java-visible):
```c
throwOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                     "Failed to initialize cipher");
```

2. **OpenSSL Error Logging** (Debug):
```c
logOpenSSLError("EVP_CipherInit_ex");
```

3. **Function Exit Logging** (Debug):
```c
logFunctionExit(functionName);
```

**Error Code Categories** (OpenSSLExceptionCodes.h):
- `OPENSSL_UNSPECIFIED` (0): Generic error
- `OPENSSL_ALLOCATION_FAILED`: Memory allocation failure
- `OPENSSL_CIPHER_*`: Cipher operation errors
- `OPENSSL_DIGEST_*`: Digest operation errors
- `OPENSSL_HMAC_*`: HMAC operation errors
- `OPENSSL_FIPS_*`: FIPS mode errors
- `OPENSSL_TAG_MISMATCH_ERROR` (-100): Authentication tag verification failed

---

## Error Handling

### Exception Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Native Code Error Occurs                                     │
│   - OpenSSL operation fails                                  │
│   - Validation fails                                         │
│   - Memory allocation fails                                  │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ throwOpenSSLException(env, code, message)                   │
│   1. Find OpenSSLException class                            │
│   2. Create exception object with code and message          │
│   3. Throw exception (sets pending exception in JNI)        │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ logOpenSSLError(prefix) [if debug enabled]                  │
│   1. ERR_get_error() → get OpenSSL error code              │
│   2. ERR_error_string_n() → convert to string              │
│   3. fprintf(stderr, ...) → log error                       │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ logFunctionExit(functionName)                               │
│   - Log function exit for debugging                         │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ Return error value to Java                                  │
│   - NULL for object returns                                 │
│   - -1 for integer returns                                  │
│   - Special codes (e.g., -100 for tag mismatch)            │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│ JNI Returns to Java                                         │
│   - Pending exception is thrown                             │
│   - Java catch block handles OpenSSLException              │
└─────────────────────────────────────────────────────────────┘
```

---

## Memory Management

### JNI Memory Rules

1. **Java Arrays**:
   - `GetByteArrayElements()` → must call `ReleaseByteArrayElements()`
   - Use `JNI_ABORT` for read-only (no copy back)
   - Use `0` for read-write (copy back)

2. **Java Strings**:
   - `GetStringUTFChars()` → must call `ReleaseStringUTFChars()`

3. **Native Memory**:
   - `malloc()` → must call `free()`
   - Always zero-initialize: `memset(ptr, 0, size)`

4. **OpenSSL Objects**:
   - `EVP_MD_fetch()` → must call `EVP_MD_free()`
   - `EVP_CIPHER_fetch()` → must call `EVP_CIPHER_free()`
   - `EVP_CIPHER_CTX_new()` → must call `EVP_CIPHER_CTX_free()`
   - `EVP_MD_CTX_new()` → must call `EVP_MD_CTX_free()`
   - `HMAC_CTX_new()` → must call `HMAC_CTX_free()`
   - `EVP_KDF_fetch()` → must call `EVP_KDF_free()`
   - `EVP_KDF_CTX_new()` → must call `EVP_KDF_CTX_free()`

### Context Lifecycle

**Creation**:
```c
OpenSSLDigestContext* ctx = mallocSafe(env, sizeof(OpenSSLDigestContext), ...);
ctx->md = fetchDigestSafe(env, context, algoName, ...);
ctx->mdCtx = createMDCtxSafe(env, functionName, ...);
```

**Usage**:
```c
// Context is reused across multiple operations
EVP_DigestUpdate(ctx->mdCtx, data, length);
EVP_DigestFinal_ex(ctx->mdCtx, output, &len);
EVP_DigestInit_ex2(ctx->mdCtx, ctx->md, NULL);  // Reset for reuse
```

**Deletion**:
```c
if (ctx->mdCtx != NULL) {
    EVP_MD_CTX_free(ctx->mdCtx);
}
if (ctx->md != NULL) {
    EVP_MD_free((EVP_MD*)ctx->md);
}
free(ctx);
```

---

## Debugging

### Debug Logging

Enable debug logging:
```bash
export OPENSSL_DEBUG=1
java -Dopenssl.debug=true YourApp
```

Debug output includes:
- Function entry/exit
- OpenSSL error messages
- Detailed operation traces (when `DEBUG_*_DETAIL` defined)
- Hexadecimal data dumps

### Logging Levels

1. **Function Tracing**:
```c
logFunctionEntry(functionName);  // "Entering Class.method"
logFunctionExit(functionName);   // "Exiting Class.method"
```

2. **Error Logging**:
```c
logOpenSSLError("EVP_CipherInit_ex");  // OpenSSL error string
```

3. **Detail Logging** (compile-time):
```c
#ifdef DEBUG_CIPHER_DETAIL
if (debug) {
    gslogMessage("DETAIL_CIPHER Encrypted %d bytes", len);
}
#endif
```

---

## Security Considerations

### 1. FIPS Mode

- Separate contexts for FIPS and non-FIPS operations
- FIPS provider loaded only when requested
- FIPS properties enabled via `EVP_default_properties_enable_fips()`
- All operations use the appropriate context

### 2. Memory Security

- Sensitive data (keys, IVs) zeroed before freeing:
```c
if (cipherCtx->key != NULL) {
    memset(cipherCtx->key, 0, cipherCtx->keyLen);
    free(cipherCtx->key);
}
```

### 3. Input Validation

- All inputs validated before use
- Array bounds checked
- Integer overflow protection
- NULL pointer checks

### 4. Thread Safety

- Context creation protected by `CRYPTO_RWLOCK`
- Singleton contexts prevent race conditions
- OpenSSL 3.x is thread-safe by design

---

## Performance Optimizations

### 1. Context Reuse

- Digest contexts reset after finalization (no recreation)
- Cipher contexts reinitialized for multiple operations
- Singleton OpenSSL contexts (no per-operation overhead)

### 2. Direct Buffer Support

- `getByteBufferPointer()` for zero-copy operations
- Direct ByteBuffer access avoids array copying

### 3. Streaming Operations

- Update/final pattern for large data
- Incremental processing reduces memory footprint

### 4. Native Performance

- Direct OpenSSL calls (no Java overhead)
- Hardware acceleration (AES-NI, etc.) via OpenSSL
- Optimized assembly implementations in OpenSSL

---

## Testing

### Test Structure

```
src/test/java/ibm/jceplus/junit/openssl/
├── TestOpenSSLDigestNative.java      # Digest tests
├── TestOpenSSLHMACNative.java        # HMAC tests
├── TestOpenSSLGCMNative.java         # GCM tests
├── TestOpenSSLCCMNative.java         # CCM tests
├── TestOpenSSLHKDFNative.java        # HKDF tests
├── TestOpenSSLPBKDF2Native.java      # PBKDF2 tests
└── TestOpenSSLKeyWrap.java           # Key wrap tests
```

### Test Categories

1. **Algorithm Tests**: Verify correct cryptographic output
2. **FIPS Tests**: Verify FIPS mode operation
3. **Interop Tests**: Verify compatibility with Java providers
4. **Edge Case Tests**: Boundary conditions, error handling
5. **Performance Tests**: Benchmark operations

---

## Conclusion

This architecture provides a robust, high-performance bridge between Java cryptographic APIs and OpenSSL's native implementations. Key strengths include:

- **Clean separation of concerns**: JNI layer, utilities, algorithm implementations
- **Consistent patterns**: All functions follow the same structure
- **Robust error handling**: Three-level error reporting
- **Memory safety**: Careful resource management
- **FIPS support**: Separate contexts for compliance
- **Performance**: Direct native calls, context reuse, streaming operations
- **Maintainability**: Well-documented, consistent coding style

The implementation serves as a reference for building JNI bridges to native cryptographic libraries.