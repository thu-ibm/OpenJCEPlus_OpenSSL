# OpenSSL FIPS Mode Setup Guide

## Overview
This guide explains how to configure and test OpenSSL FIPS mode with the OpenJCEPlus provider.

## Prerequisites

### 1. FIPS-Enabled OpenSSL Installation
You need OpenSSL 3.x with FIPS module installed. Verify with:
```cmd
openssl list -providers
```

Expected output should show both providers:
```
Providers:
  base
    name: OpenSSL Base Provider
    version: 3.0.x
    status: active
  fips
    name: OpenSSL FIPS Provider
    version: 3.0.x
    status: active
```

### 2. Environment Configuration
Set the `OPENSSL_HOME` environment variable to point to your FIPS-enabled OpenSSL installation:

**Windows:**
```cmd
setx OPENSSL_HOME "C:\OpenSSL-v3-FIPS"
```

**Verify:**
```cmd
echo %OPENSSL_HOME%
```

## Building with FIPS Support

### 1. Clean Previous Build
```cmd
cd src\main\native\openssl
nmake -f openssl.win64.mak clean
```

### 2. Rebuild Native DLL
The build script automatically uses `OPENSSL_HOME`:
```cmd
buildNativeOpenSSL_Win64_AutoEnv.bat
```

The DLL will be built against the FIPS-enabled OpenSSL libraries at `%OPENSSL_HOME%\lib`.

### 3. Deploy DLL
Copy the built DLL to your JVM's bin directory:
```cmd
copy target\buildopensslwin\host64\libjgskit_openssl_64.dll %JAVA_HOME%\bin\
```

## Running FIPS Tests

### 1. Core Tests (Non-FIPS)
These tests work with any OpenSSL 3.x installation:
```cmd
run_all_openssl_core_tests.bat
```

### 2. FIPS Tests
These tests require FIPS-enabled OpenSSL:
```cmd
run_openssl_fips_tests.bat
```

The script will:
- Check if `OPENSSL_HOME` is set
- Verify FIPS provider is available
- Run all FIPS-specific tests

## Troubleshooting

### Tests Skip with "FIPS mode not available"

**Cause:** The native DLL was built against non-FIPS OpenSSL libraries.

**Solution:**
1. Verify FIPS provider: `openssl list -providers`
2. Set `OPENSSL_HOME` to FIPS-enabled OpenSSL
3. Rebuild the DLL: `buildNativeOpenSSL_Win64_AutoEnv.bat`
4. Redeploy to JVM: `copy target\buildopensslwin\host64\libjgskit_openssl_64.dll %JAVA_HOME%\bin\`

### FIPS Provider Not Found

**Cause:** OpenSSL installation doesn't have FIPS module or it's not configured.

**Solution:**
1. Install OpenSSL with FIPS module
2. Configure `openssl.cnf` to load FIPS provider
3. Verify with: `openssl list -providers`

### DLL Load Errors

**Cause:** Runtime can't find FIPS-enabled OpenSSL DLLs.

**Solution:**
Ensure `%OPENSSL_HOME%\bin` is in your PATH:
```cmd
set PATH=%OPENSSL_HOME%\bin;%PATH%
```

## Verification

### Check Current Configuration
```cmd
REM Check OPENSSL_HOME
echo %OPENSSL_HOME%

REM Verify FIPS provider
"%OPENSSL_HOME%\bin\openssl.exe" list -providers

REM Check DLL location
where libjgskit_openssl_64.dll
```

### Test FIPS Mode
```cmd
REM Run FIPS tests
run_openssl_fips_tests.bat

REM Expected: Tests should run (not skip)
REM Look for: "Tests run: 39, Failures: 0, Errors: 0, Skipped: 0"
```

## Architecture Notes

### FIPS Context Creation
The native code checks FIPS availability at runtime:
- [`OpenSSLUtils.c:113-128`](src/main/native/openssl/OpenSSLUtils.c:113): `isFIPSSupported()` checks if FIPS provider can be loaded
- [`OpenSSLUtils.c:137-143`](src/main/native/openssl/OpenSSLUtils.c:137): Throws exception if FIPS requested but unavailable
- [`OpenSSLUtils.c:166-199`](src/main/native/openssl/OpenSSLUtils.c:166): Loads FIPS and base providers, enables FIPS mode

### Java Layer
- [`NativeOpenSSLAdapterFIPS.java`](src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLAdapterFIPS.java): FIPS adapter that requests FIPS mode
- Platform certification check ensures FIPS only runs on certified platforms
- Graceful fallback to non-FIPS on uncertified platforms with warnings

## Summary

1. **Install** FIPS-enabled OpenSSL
2. **Configure** `OPENSSL_HOME` environment variable
3. **Build** native DLL against FIPS libraries
4. **Deploy** DLL to JVM bin directory
5. **Test** with `run_openssl_fips_tests.bat`