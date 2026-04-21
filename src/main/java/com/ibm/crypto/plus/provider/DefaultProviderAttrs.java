/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

/**
 * Default provider attributes and service definitions.
 * This class provides a default configuration string that can be used
 * to initialize the OpenJCEPlus provider with standard services.
 * 
 * The configuration includes:
 * - Provider name and description
 * - Backend selector (OCK or OpenSSL)
 * - Service definitions for cryptographic algorithms
 */
public class DefaultProviderAttrs {

    /**
     * Default provider configuration string in Java Properties format.
     * 
     * Format:
     * - name = provider name
     * - description = provider description
     * - backend = backend implementation (OCK or OpenSSL)
     * - Service.{Type}.{Algorithm} = implementation class
     * - Service.{Type}.alias.{Algorithm}.{index} = alias name
     * - Service.{Type}.attr.{Algorithm}.{attribute} = attribute value
     */
    public static String defaultProvAttrs = 
        "name = OpenJCEPlus\n" +
        "description = OpenJCEPlus Provider\n" +
        "# Backend selector: OCK (default) or OpenSSL\n" +
        "backend = OCK\n" +
        "#\n" +
        "# Algorithm parameter generation engines\n" +
        "#\n" +
        "Service.AlgorithmParameterGenerator.DiffieHellman = com.ibm.crypto.plus.provider.DHParameterGenerator\n" +
        "Service.AlgorithmParameterGenerator.alias.DiffieHellman.0 = DH\n" +
        "Service.AlgorithmParameterGenerator.alias.DiffieHellman.1 = 1.2.840.113549.1.3.1\n" +
        "Service.AlgorithmParameterGenerator.DSA = com.ibm.crypto.plus.provider.DSAParameterGenerator\n" +
        "Service.AlgorithmParameterGenerator.alias.DSA.0 = 1.2.840.10040.4.1\n" +
        "Service.AlgorithmParameterGenerator.EC = com.ibm.crypto.plus.provider.ECParameterGenerator\n" +
        "Service.AlgorithmParameterGenerator.GCM = com.ibm.crypto.plus.provider.GCMParameterGenerator\n" +
        "Service.AlgorithmParameterGenerator.CCM = com.ibm.crypto.plus.provider.CCMParameterGenerator\n" +
        "#\n" +
        "# Algorithm parameters\n" +
        "#\n" +
        "Service.AlgorithmParameters.AES = com.ibm.crypto.plus.provider.AESParameters\n" +
        "Service.AlgorithmParameters.ChaCha20 = com.ibm.crypto.plus.provider.ChaCha20Parameters\n" +
        "Service.AlgorithmParameters.ChaCha20-Poly1305 = com.ibm.crypto.plus.provider.ChaCha20Poly1305Parameters\n" +
        "Service.AlgorithmParameters.DESede = com.ibm.crypto.plus.provider.DESedeParameters\n" +
        "Service.AlgorithmParameters.alias.DESede.0 = TripleDES\n" +
        "Service.AlgorithmParameters.DiffieHellman = com.ibm.crypto.plus.provider.DHParameters\n" +
        "Service.AlgorithmParameters.alias.DiffieHellman.0 = DH\n" +
        "Service.AlgorithmParameters.alias.DiffieHellman.1 = 1.2.840.113549.1.3.1\n" +
        "Service.AlgorithmParameters.DSA = com.ibm.crypto.plus.provider.DSAParameters\n" +
        "Service.AlgorithmParameters.alias.DSA.0 = 1.2.840.10040.4.1\n" +
        "Service.AlgorithmParameters.EC = com.ibm.crypto.plus.provider.ECParameters\n" +
        "Service.AlgorithmParameters.GCM = com.ibm.crypto.plus.provider.GCMParameters\n" +
        "Service.AlgorithmParameters.CCM = com.ibm.crypto.plus.provider.CCMParameters\n" +
        "Service.AlgorithmParameters.OAEP = com.ibm.crypto.plus.provider.OAEPParameters\n" +
        "Service.AlgorithmParameters.RSAPSS = com.ibm.crypto.plus.provider.PSSParameters\n" +
        "#\n" +
        "# Cipher engines\n" +
        "#\n" +
        "Service.Cipher.AES = com.ibm.crypto.plus.provider.AESCipher$General\n" +
        "Service.Cipher.AES/CBC/NoPadding = com.ibm.crypto.plus.provider.AESCipher$CBC_NoPadding\n" +
        "Service.Cipher.AES/CBC/PKCS5Padding = com.ibm.crypto.plus.provider.AESCipher$CBC_PKCS5Padding\n" +
        "Service.Cipher.AES/ECB/NoPadding = com.ibm.crypto.plus.provider.AESCipher$ECB_NoPadding\n" +
        "Service.Cipher.AES/ECB/PKCS5Padding = com.ibm.crypto.plus.provider.AESCipher$ECB_PKCS5Padding\n" +
        "Service.Cipher.AES/GCM/NoPadding = com.ibm.crypto.plus.provider.AESGCMCipher\n" +
        "Service.Cipher.AES/CCM/NoPadding = com.ibm.crypto.plus.provider.AESCCMCipher\n" +
        "Service.Cipher.ChaCha20 = com.ibm.crypto.plus.provider.ChaCha20Cipher\n" +
        "Service.Cipher.ChaCha20-Poly1305 = com.ibm.crypto.plus.provider.ChaCha20Poly1305Cipher\n" +
        "Service.Cipher.DESede = com.ibm.crypto.plus.provider.DESedeCipher$General\n" +
        "Service.Cipher.alias.DESede.0 = TripleDES\n" +
        "Service.Cipher.RSA = com.ibm.crypto.plus.provider.RSACipher\n" +
        "#\n" +
        "# Key agreement\n" +
        "#\n" +
        "Service.KeyAgreement.DiffieHellman = com.ibm.crypto.plus.provider.DHKeyAgreement\n" +
        "Service.KeyAgreement.alias.DiffieHellman.0 = DH\n" +
        "Service.KeyAgreement.ECDH = com.ibm.crypto.plus.provider.ECDHKeyAgreement\n" +
        "Service.KeyAgreement.XDH = com.ibm.crypto.plus.provider.XDHKeyAgreement\n" +
        "#\n" +
        "# Key factories\n" +
        "#\n" +
        "Service.KeyFactory.DiffieHellman = com.ibm.crypto.plus.provider.DHKeyFactory\n" +
        "Service.KeyFactory.alias.DiffieHellman.0 = DH\n" +
        "Service.KeyFactory.DSA = com.ibm.crypto.plus.provider.DSAKeyFactory\n" +
        "Service.KeyFactory.EC = com.ibm.crypto.plus.provider.ECKeyFactory\n" +
        "Service.KeyFactory.XDH = com.ibm.crypto.plus.provider.XDHKeyFactory\n" +
        "Service.KeyFactory.X25519 = com.ibm.crypto.plus.provider.XDHKeyFactory$X25519\n" +
        "Service.KeyFactory.X448 = com.ibm.crypto.plus.provider.XDHKeyFactory$X448\n" +
        "Service.KeyFactory.EdDSA = com.ibm.crypto.plus.provider.EdDSAKeyFactory\n" +
        "Service.KeyFactory.Ed25519 = com.ibm.crypto.plus.provider.EdDSAKeyFactory$Ed25519\n" +
        "Service.KeyFactory.Ed448 = com.ibm.crypto.plus.provider.EdDSAKeyFactory$Ed448\n" +
        "Service.KeyFactory.RSA = com.ibm.crypto.plus.provider.RSAKeyFactory\n" +
        "Service.KeyFactory.RSASSA-PSS = com.ibm.crypto.plus.provider.RSAKeyFactory$PSS\n" +
        "#\n" +
        "# Key generators\n" +
        "#\n" +
        "Service.KeyGenerator.AES = com.ibm.crypto.plus.provider.AESKeyGenerator\n" +
        "Service.KeyGenerator.ChaCha20 = com.ibm.crypto.plus.provider.ChaCha20KeyGenerator\n" +
        "Service.KeyGenerator.DESede = com.ibm.crypto.plus.provider.DESedeKeyGenerator\n" +
        "Service.KeyGenerator.alias.DESede.0 = TripleDES\n" +
        "Service.KeyGenerator.HmacSHA1 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA1$KeyGenerator\n" +
        "Service.KeyGenerator.HmacSHA256 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA256$KeyGenerator\n" +
        "Service.KeyGenerator.HmacSHA384 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA384$KeyGenerator\n" +
        "Service.KeyGenerator.HmacSHA512 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA512$KeyGenerator\n" +
        "#\n" +
        "# Key pair generators\n" +
        "#\n" +
        "Service.KeyPairGenerator.DiffieHellman = com.ibm.crypto.plus.provider.DHKeyPairGenerator\n" +
        "Service.KeyPairGenerator.alias.DiffieHellman.0 = DH\n" +
        "Service.KeyPairGenerator.DSA = com.ibm.crypto.plus.provider.DSAKeyPairGenerator\n" +
        "Service.KeyPairGenerator.EC = com.ibm.crypto.plus.provider.ECKeyPairGenerator\n" +
        "Service.KeyPairGenerator.XDH = com.ibm.crypto.plus.provider.XDHKeyPairGenerator\n" +
        "Service.KeyPairGenerator.X25519 = com.ibm.crypto.plus.provider.XDHKeyPairGenerator$X25519\n" +
        "Service.KeyPairGenerator.X448 = com.ibm.crypto.plus.provider.XDHKeyPairGenerator$X448\n" +
        "Service.KeyPairGenerator.EdDSA = com.ibm.crypto.plus.provider.EdDSAKeyPairGenerator\n" +
        "Service.KeyPairGenerator.Ed25519 = com.ibm.crypto.plus.provider.EdDSAKeyPairGenerator$Ed25519\n" +
        "Service.KeyPairGenerator.Ed448 = com.ibm.crypto.plus.provider.EdDSAKeyPairGenerator$Ed448\n" +
        "Service.KeyPairGenerator.RSA = com.ibm.crypto.plus.provider.RSAKeyPairGenerator\n" +
        "Service.KeyPairGenerator.RSASSA-PSS = com.ibm.crypto.plus.provider.RSAKeyPairGenerator$PSS\n" +
        "#\n" +
        "# Message authentication codes\n" +
        "#\n" +
        "Service.Mac.HmacSHA1 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA1\n" +
        "Service.Mac.HmacSHA256 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA256\n" +
        "Service.Mac.HmacSHA384 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA384\n" +
        "Service.Mac.HmacSHA512 = com.ibm.crypto.plus.provider.HmacCore$HmacSHA512\n" +
        "#\n" +
        "# Message digests\n" +
        "#\n" +
        "Service.MessageDigest.SHA-1 = com.ibm.crypto.plus.provider.SHA$SHA1\n" +
        "Service.MessageDigest.alias.SHA-1.0 = SHA1\n" +
        "Service.MessageDigest.SHA-256 = com.ibm.crypto.plus.provider.SHA$SHA256\n" +
        "Service.MessageDigest.alias.SHA-256.0 = SHA256\n" +
        "Service.MessageDigest.SHA-384 = com.ibm.crypto.plus.provider.SHA$SHA384\n" +
        "Service.MessageDigest.alias.SHA-384.0 = SHA384\n" +
        "Service.MessageDigest.SHA-512 = com.ibm.crypto.plus.provider.SHA$SHA512\n" +
        "Service.MessageDigest.alias.SHA-512.0 = SHA512\n" +
        "#\n" +
        "# Signatures\n" +
        "#\n" +
        "Service.Signature.SHA1withDSA = com.ibm.crypto.plus.provider.DSASignature$SHA1withDSA\n" +
        "Service.Signature.SHA256withDSA = com.ibm.crypto.plus.provider.DSASignature$SHA256withDSA\n" +
        "Service.Signature.SHA1withECDSA = com.ibm.crypto.plus.provider.ECDSASignature$SHA1\n" +
        "Service.Signature.SHA256withECDSA = com.ibm.crypto.plus.provider.ECDSASignature$SHA256\n" +
        "Service.Signature.SHA384withECDSA = com.ibm.crypto.plus.provider.ECDSASignature$SHA384\n" +
        "Service.Signature.SHA512withECDSA = com.ibm.crypto.plus.provider.ECDSASignature$SHA512\n" +
        "Service.Signature.Ed25519 = com.ibm.crypto.plus.provider.EdDSASignature$Ed25519\n" +
        "Service.Signature.Ed448 = com.ibm.crypto.plus.provider.EdDSASignature$Ed448\n" +
        "Service.Signature.SHA1withRSA = com.ibm.crypto.plus.provider.RSASignature$SHA1withRSA\n" +
        "Service.Signature.SHA256withRSA = com.ibm.crypto.plus.provider.RSASignature$SHA256withRSA\n" +
        "Service.Signature.SHA384withRSA = com.ibm.crypto.plus.provider.RSASignature$SHA384withRSA\n" +
        "Service.Signature.SHA512withRSA = com.ibm.crypto.plus.provider.RSASignature$SHA512withRSA\n" +
        "Service.Signature.RSASSA-PSS = com.ibm.crypto.plus.provider.RSASignature$RSAPSS\n";
}


