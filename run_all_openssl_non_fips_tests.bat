@echo off
REM ========================================
REM Run All Core OpenSSL Tests
REM ========================================
REM
REM This script runs all core OpenSSL integration tests in a single Maven execution:
REM - TestOpenSSLNativeInterface (Native Interface: JNI boundary tests)
REM - TestOpenSSLSymmetricCipherNative (Symmetric Cipher: AES, DES, 3DES, ChaCha20)
REM - TestOpenSSLGCMNative (GCM Native: Galois/Counter Mode)
REM - TestOpenSSLCCMNative (CCM Native: Counter with CBC-MAC)
REM - TestOpenSSLKeyWrap (Key Wrap/Unwrap - Native tests only)
REM - TestOpenSSLDigestNative (Digest: SHA-256, SHA-512, etc.)
REM - TestOpenSSLHMACNative (HMAC: Hash-based Message Authentication Code)
REM - TestOpenSSLHKDFNative (HKDF: HMAC-based Key Derivation Function)
REM - TestOpenSSLPBKDF2Native (PBKDF2: Password-Based Key Derivation Function 2)
REM
REM ========================================

echo.
echo ========================================
echo Running All Core OpenSSL Tests
echo ========================================
echo.

REM Set library paths for native libraries
set "OCK_LIB_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK"
set "OPENSSL_LIB_PATH=C:\OpenSSL-v3\bin"
set "JGSKIT_LIB_PATH=C:\Users\Administrator\Downloads\opensdk\semeru_ibm\jdk\bin"

REM Check if OPENSSL_HOME is set and add bin directory to PATH
if defined OPENSSL_HOME (
    echo OPENSSL_HOME: %OPENSSL_HOME%
    set "PATH=%OPENSSL_HOME%\bin;%PATH%"
) else (
    echo WARNING: OPENSSL_HOME not set - OpenSSL DLLs may not be found
)

REM Add all library directories to PATH
set "PATH=%OCK_LIB_PATH%;%OPENSSL_LIB_PATH%;%JGSKIT_LIB_PATH%;%PATH%"

echo Library paths:
echo - OCK:     %OCK_LIB_PATH%
echo - OpenSSL: %OPENSSL_LIB_PATH%
echo - JGSKit:  %JGSKIT_LIB_PATH%
echo.

echo Running all OpenSSL core tests...
echo.
echo Tests included:
echo   1. TestOpenSSLNativeInterface (Native Interface)
echo   2. TestOpenSSLSymmetricCipherNative (Symmetric Cipher)
echo   3. TestOpenSSLGCMNative (GCM Native)
echo   4. TestOpenSSLCCMNative (CCM Native)
echo   5. TestOpenSSLDigestNative (Digest)
echo   6. TestOpenSSLHMACNative (HMAC)
echo   7. TestOpenSSLHKDFNative (HKDF)
echo   8. TestOpenSSLPBKDF2Native (PBKDF2)
echo.

mvn test -Dtest=ibm.jceplus.junit.openssl.TestOpenSSLNativeInterface,ibm.jceplus.junit.openssl.TestOpenSSLSymmetricCipherNative,ibm.jceplus.junit.openssl.TestOpenSSLGCMNative,ibm.jceplus.junit.openssl.TestOpenSSLCCMNative,ibm.jceplus.junit.openssl.TestOpenSSLDigestNative,ibm.jceplus.junit.openssl.TestOpenSSLHMACNative,ibm.jceplus.junit.openssl.TestOpenSSLHKDFNative,ibm.jceplus.junit.openssl.TestOpenSSLPBKDF2Native ^
    -DfailIfNoTests=false ^
    "-Dock.library.path=%OCK_LIB_PATH%" ^
    "-Dopenssl.library.path=%OPENSSL_LIB_PATH%" ^
    "-Djgskit.library.path=%JGSKIT_LIB_PATH%" ^
    "-DargLine=--add-opens openjceplus/ibm.jceplus.junit.openssl=ALL-UNNAMED"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo All tests completed successfully!
    echo ========================================
    echo.
    echo All 8 OpenSSL core test suites passed
) else (
    echo.
    echo ========================================
    echo Tests failed with error code %ERRORLEVEL%
    echo ========================================
    echo.
    echo Common issues:
    echo 1. OpenSSL native library not built or not on PATH
    echo 2. jgskit_openssl library not found
    echo 3. Native JNI wiring mismatch
    echo 4. OpenSSL implementation/runtime failure
    echo.
    echo Check the test output above for specific failures
)

pause


