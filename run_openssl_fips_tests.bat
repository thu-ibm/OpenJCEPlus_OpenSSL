@echo off
REM Run all OpenSSL FIPS mode tests
REM These tests verify that all OpenSSL native operations work correctly in FIPS mode
REM
REM IMPORTANT: For FIPS tests to run, you must:
REM 1. Set OPENSSL_HOME to a FIPS-enabled OpenSSL installation (e.g., C:\OpenSSL-v3-FIPS)
REM 2. Rebuild the native DLL against the FIPS-enabled OpenSSL libraries
REM 3. Verify FIPS provider is available: openssl list -providers

echo ========================================
echo Running OpenSSL FIPS Mode Tests
echo ========================================
echo.

REM Check if OPENSSL_HOME is set
if not defined OPENSSL_HOME (
    echo ERROR: OPENSSL_HOME environment variable is not set
    echo.
    echo For FIPS tests, OPENSSL_HOME must point to a FIPS-enabled OpenSSL installation.
    echo Example: set OPENSSL_HOME=C:\OpenSSL-v3-FIPS
    echo.
    echo To verify FIPS support, run: openssl list -providers
    echo You should see both 'base' and 'fips' providers listed.
    exit /b 1
)

echo OPENSSL_HOME: %OPENSSL_HOME%

REM Verify FIPS provider is available
echo.
echo Checking for FIPS provider...
"%OPENSSL_HOME%\bin\openssl.exe" list -providers | findstr /C:"fips" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo WARNING: FIPS provider not found in OpenSSL installation
    echo.
    echo The OpenSSL installation at %OPENSSL_HOME% does not have FIPS support.
    echo FIPS tests will be skipped.
    echo.
    echo To enable FIPS:
    echo 1. Install OpenSSL with FIPS module
    echo 2. Configure openssl.cnf to load FIPS provider
    echo 3. Rebuild the native DLL against FIPS-enabled OpenSSL
    echo.
    pause
) else (
    echo FIPS provider found - tests will attempt to run
)
echo.

REM Use environment variables with fallback defaults
if not defined OCK_LIB_PATH set "OCK_LIB_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK"
if not defined JGSKIT_LIB_PATH (
    if defined JAVA_HOME (
        set "JGSKIT_LIB_PATH=%JAVA_HOME%\bin"
    ) else (
        set "JGSKIT_LIB_PATH=C:\Users\Administrator\Downloads\opensdk\semeru\jdk\bin"
    )
)

REM Set OpenSSL library path from OPENSSL_HOME
set "OPENSSL_LIB_PATH=%OPENSSL_HOME%\bin"

REM Add all library directories to PATH
set "PATH=%OCK_LIB_PATH%;%OPENSSL_LIB_PATH%;%JGSKIT_LIB_PATH%;%PATH%"

echo Library paths:
echo - OCK:     %OCK_LIB_PATH%
echo - OpenSSL: %OPENSSL_LIB_PATH%
echo - JGSKit:  %JGSKIT_LIB_PATH%
echo.

REM Clean and compile once, then run all FIPS tests
echo Cleaning and compiling...
call mvn clean test-compile -DskipTests ^
    "-Dock.library.path=%OCK_LIB_PATH%" ^
    "-Dopenssl.library.path=%OPENSSL_LIB_PATH%" ^
    "-Djgskit.library.path=%JGSKIT_LIB_PATH%"
if %ERRORLEVEL% neq 0 (
    echo Maven compilation failed!
    exit /b 1
)

echo.
echo ========================================
echo Running All FIPS Tests
echo ========================================
echo.
echo Tests included:
echo   1. TestOpenSSLPBKDF2FIPS (PBKDF2)
echo   2. TestOpenSSLHKDFFIPS (HKDF)
echo   3. TestOpenSSLCCMFIPS (CCM)
echo   4. TestOpenSSLSymmetricCipherFIPS (Symmetric Cipher)
echo.

call mvn test ^
    -Dtest=ibm.jceplus.junit.openssl.TestOpenSSLPBKDF2FIPS,ibm.jceplus.junit.openssl.TestOpenSSLHKDFFIPS,ibm.jceplus.junit.openssl.TestOpenSSLCCMFIPS,ibm.jceplus.junit.openssl.TestOpenSSLSymmetricCipherFIPS ^
    -DfailIfNoTests=false ^
    "-Dock.library.path=%OCK_LIB_PATH%" ^
    "-Dopenssl.library.path=%OPENSSL_LIB_PATH%" ^
    "-Djgskit.library.path=%JGSKIT_LIB_PATH%" ^
    "-DargLine=--add-opens openjceplus/ibm.jceplus.junit.openssl=ALL-UNNAMED"
if %ERRORLEVEL% neq 0 (
    echo FIPS tests failed!
    exit /b 1
)

echo.
echo ========================================
echo All FIPS Mode Tests Passed!
echo ========================================

echo.
echo Summary:
echo - Native Interface (JNI boundary, FIPS mode detection)
echo - Digest (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)
echo - GCM (encrypt/decrypt, streaming, tag validation)
echo - HMAC (SHA-1, SHA-256, SHA-384, SHA-512)
echo - PBKDF2 (SHA-1, SHA-256, SHA-512)
echo - HKDF (extract, expand, derive)
echo - CCM (encrypt/decrypt, tag validation, various tag lengths)
echo - Symmetric Cipher (AES, 3DES in FIPS mode, algorithm rejection)
echo.


