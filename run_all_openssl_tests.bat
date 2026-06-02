@echo off
REM Script to run all OpenSSL tests (both FIPS and Native modes)
REM Tests from ibm.jceplus.junit.openssl package

echo ========================================
echo Running All OpenSSL Tests
echo ========================================
echo.

REM Set OpenSSL paths (but don't set OPENSSL_CONF yet to avoid Maven build issues)
set "OPENSSL_HOME=C:\OpenSSL-v3-FIPS"
set "OPENSSL_CONF_PATH=%OPENSSL_HOME%\ssl\openssl.cnf"

REM Set library paths
set "JGSKIT_PATH=C:\Users\Administrator\Downloads\opensdk\semeru_ibm\jdk\bin"
set "OCK_PATH=C:\Users\Administrator\dev\OpenJDKDev\OCK"
set "OPENSSL_PATH=%OPENSSL_HOME%\bin"

echo Environment Configuration:
echo - OPENSSL_HOME: %OPENSSL_HOME%
echo - OPENSSL_CONF will be set: %OPENSSL_CONF_PATH%
echo - Library paths:
echo   * JGSKit:  %JGSKIT_PATH%
echo   * OCK:     %OCK_PATH%
echo   * OpenSSL: %OPENSSL_PATH%
echo.

REM Check for FIPS provider
echo Checking for FIPS provider...
"%OPENSSL_HOME%\bin\openssl.exe" list -providers 2>nul | findstr /C:"fips" >nul
if %errorlevel% equ 0 (
    echo [OK] FIPS provider found - FIPS tests will run in FIPS mode
) else (
    echo [WARNING] FIPS provider not found - FIPS tests may be skipped
)
echo.

echo ========================================
echo Running OpenSSL Test Suite
echo ========================================
echo.
echo This will run OpenSSL tests (excluding OCK-dependent tests):
echo.
echo FIPS Mode Tests:
echo   - TestOpenSSLCCMFIPS
echo   - TestOpenSSLDigestFIPS
echo   - TestOpenSSLGCMFIPS
echo   - TestOpenSSLHKDFFIPS
echo   - TestOpenSSLHMACFIPS
echo   - TestOpenSSLPBKDF2FIPS
echo   - TestOpenSSLSymmetricCipherFIPS
echo.
echo Native Mode Tests:
echo   - TestOpenSSLCCMNative
echo   - TestOpenSSLDigestNative
echo   - TestOpenSSLGCMNative
echo   - TestOpenSSLHKDFNative
echo   - TestOpenSSLHMACNative
echo   - TestOpenSSLPBKDF2Native
echo   - TestOpenSSLSymmetricCipherNative
echo.
echo Other Tests:
echo   - TestOpenSSLNativeInterface
echo.
echo Excluded (OCK-dependent):
echo   - TestAESCCMOpenSSL
echo   - TestAESOpenSSLConfig
echo   - TestOpenSSLGCMCipher
echo   - TestOpenSSLKeyWrap
echo.
echo ========================================
echo.

REM Set OPENSSL_CONF for test execution
set "OPENSSL_CONF=%OPENSSL_CONF_PATH%"

REM Run OpenSSL tests excluding OCK-dependent tests
REM Note: OpenSSL warnings during Maven build phases are harmless and can be ignored
mvn test -Dtest=ibm.jceplus.junit.openssl.**,!ibm.jceplus.junit.openssl.TestAESCCMOpenSSL,!ibm.jceplus.junit.openssl.TestAESOpenSSLConfig,!ibm.jceplus.junit.openssl.TestOpenSSLGCMCipher,!ibm.jceplus.junit.openssl.TestOpenSSLKeyWrap -Djgskit.library.path=%JGSKIT_PATH% -Dock.library.path=%OCK_PATH% -Dopenssl.library.path=%OPENSSL_PATH%

REM Unset OPENSSL_CONF after tests
set "OPENSSL_CONF="

echo.
echo ========================================
echo Test execution completed
echo ========================================
echo.
echo Check the output above for test results.
echo.
pause


