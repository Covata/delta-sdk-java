/*
 * Copyright 2016 Covata Limited or its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.covata.delta.sdk.crypto;

import com.covata.delta.sdk.DeltaClientConfig;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.google.common.io.BaseEncoding;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Provides functionality for client side cryptography.
 * <p>
 * The service can be configured via the <code>DeltaClientConfig</code>,
 * so that the symmetric key, asymmetric key and random number generator
 * algorithms to be changed.
 * </p>
 */
public class CryptoService {

    private static final Charset STRING_ENCODING_CHARSET = Charset.forName("UTF-8");

    private final DeltaClientConfig config;

    private final DeltaKeyStore keyStore;

    /**
     * Instantiates a new cryptography service
     *
     * @param config configuration for the cryptography service
     * @param keyStore the key store used by the cryptography service
     */
    public CryptoService(DeltaClientConfig config, DeltaKeyStore keyStore) {
        this.config = config;
        this.keyStore = keyStore;
    }

    /**
     * Encrypts <code>plainText</code> using <code>encryptionKey</code>.
     *
     * @param plainText the file to be encrypted
     * @param key the key to be used for encryption
     * @param iv the initialisation vector
     * @return the encrypted plainText in base 64
     * @throws DeltaClientException on exception during encryption
     */
    public String encrypt(String plainText, SecretKey key, byte[] iv)
            throws DeltaClientException {
        return encrypt(plainText.getBytes(STRING_ENCODING_CHARSET), key, iv);
    }

    /**
     * Encrypts <code>file</code> using <code>encryptionKey</code>.
     *
     * @param file the file to be encrypted
     * @param key the key to be used for encryption
     * @param iv the initialisation vector
     * @return the encrypted <code>File</code> in base 64
     * @throws DeltaClientException on exception during encryption
     * @throws IOException on exception reading file
     */
    public String encrypt(File file, SecretKey key, byte[] iv)
            throws IOException, DeltaClientException {
        byte[] inputBytes;
        try (FileInputStream inputStream = new FileInputStream(file)) {
            inputBytes = new byte[(int) file.length()];
            inputStream.read(inputBytes);
            return encrypt(inputBytes, key, iv);
        }
    }

    /**
     * Encrypts <code>bytes</code> using <code>key</code>.
     *
     * @param bytes the bytes to be encrypted
     * @param key the key to be used for encryption
     * @param iv the initialisation vector
     * @return the encrypted bytes in base 64
     * @throws DeltaClientException on exception during encryption
     */
    public String encrypt(byte[] bytes, SecretKey key, byte[] iv)
            throws DeltaClientException {
        if (key == null || iv == null) {
            throw new IllegalArgumentException("Key or IV cannot be null");
        }
        try {
            Cipher cipher = Cipher.getInstance(config.getSymmetricKeyAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] cipherText = cipher.doFinal(bytes);
            return BaseEncoding.base64().encode(cipherText);
        } catch (Exception e) {
            throw new DeltaClientException(e);
        }
    }

    /**
     * Generates a 128-bit initialisation vector.
     *
     * @return the initialisation vector as a byte array
     * @throws DeltaClientException on exception generating initialisation vector
     */
    public byte[] generateInitialisationVector()
            throws DeltaClientException {
        try {
            SecureRandom r = SecureRandom.getInstance(config.getRandomGenAlgorithm());
            byte[] iv = new byte[16];
            r.nextBytes(iv);
            return iv;
        } catch (NoSuchAlgorithmException e) {
            throw new DeltaClientException("Error generating initialisation vector", e);
        }
    }

    /**
     * Decrypts <code>ciphertext</code> into a string value.
     *
     * @param cipherText the data to be decrypted
     * @param encryptionKey the key to be used for decryption
     * @param iv the initialisation vector
     * @return the decrypted string
     * @throws DeltaClientException on exception during decryption
     */
    public String decrypt(byte[] cipherText, SecretKey encryptionKey, byte[] iv)
            throws DeltaClientException {
        try {
            Cipher cipher = Cipher.getInstance(config.getSymmetricKeyAlgorithm());
            GCMParameterSpec params = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, params);

            return new String(cipher.doFinal(cipherText), STRING_ENCODING_CHARSET);
        } catch (Exception e) {
            throw new DeltaClientException("Error decrypting cipher text", e);
        }
    }

    /**
     * Decrypts the ciphertext using the specified secret key
     * (itself encrypted with the private encryption key of owning identity)
     * and initialisation vector.
     *
     * @param cipherText the data to be decrypted
     * @param encryptedKey the private encryption key
     * @param iv the initialisation vector
     * @param keyOwnerId the identity owner of the encrypted key
     * @return the decrypted string
     * @throws DeltaClientException on exception during decryption
     */
    public String decrypt(String cipherText, String encryptedKey,
                          byte[] iv, String keyOwnerId)
            throws DeltaClientException {

        String keyString = decryptWithPrivateKey(
                encryptedKey,
                keyStore.getPrivateEncryptionKey(keyOwnerId));

        return decrypt(
                BaseEncoding.base64().decode(cipherText),
                getSymmetricKey(keyString), iv);
    }


    /**
     * Encrypts the given secret key with the public key.
     *
     * @param key the key to encrypt
     * @param encryptionKey the public encryption key
     * @return the encrypted key as a base64 encoded string
     * @throws DeltaClientException on exception during encryption
     */
    public String encryptKeyWithPublicKey(SecretKey key, PublicKey encryptionKey)
            throws DeltaClientException {
        if (key == null || encryptionKey == null) {
            throw new IllegalArgumentException("Text or encryption key is null");
        }
        byte[] bytes = key.getEncoded();
        try {
            Cipher cipher = Cipher.getInstance(config.getAsymmetricKeyAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            return BaseEncoding.base64().encode(cipher.doFinal(bytes));
        } catch (Exception e) {
            throw new DeltaClientException("Error encrypting secret key", e);
        }
    }

    /**
     * Decrypts the given secret key (encoded as a base 64 string) with the
     * private key.
     *
     * @param key the secret key to decrypt (encoded in base 64)
     * @param encryptionKey the private encryption key
     * @return the decrypted key as a base64 encoded string
     * @throws DeltaClientException on exception during decryption
     */
    public String decryptWithPrivateKey(String key, PrivateKey encryptionKey)
            throws DeltaClientException {
        if (key == null || encryptionKey == null) {
            throw new IllegalArgumentException("Text or encryption key is null");
        }
        byte[] bytes = BaseEncoding.base64().decode(key);
        try {
            Cipher cipher = Cipher.getInstance(config.getAsymmetricKeyAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
            return BaseEncoding.base64().encode(cipher.doFinal(bytes));
        } catch (Exception e) {
            throw new DeltaClientException("Error decrypting secret key", e);
        }
    }

    /**
     * Generates a public-private key pair.
     *
     * @return the generated key pair
     * @throws DeltaClientException on exception during key generation
     */
    public KeyPair generatePublicPrivateKey() throws DeltaClientException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096, new SecureRandom());
            return keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new DeltaClientException("Error generating key pair", e);
        }
    }

    /**
     * Generates a 256-bit secret key.
     *
     * @return the generated secret key
     * @throws DeltaClientException on exception during key generation
     */
    public SecretKey generateSecretKey() throws DeltaClientException {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, random);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new DeltaClientException("Error generating symmetric key", e);
        }
    }

    /**
     * Transforms the private key, encoded as a base 64 string, into a private
     * key instance.
     *
     * @param key private key as a base64 encoded string
     * @return the private key
     * @throws DeltaClientException on error creating private key from string
     */
    public PrivateKey getPrivateKey(String key) throws DeltaClientException {
        try {
            byte[] byteKey = BaseEncoding.base64().decode(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(byteKey);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException e) {
            throw new DeltaClientException("Error creating private key from string", e);
        }
    }

    /**
     * Transforms the public key, encoded as a base 64 string, into a public
     * key instance.
     *
     * @param key public key as a base64 encoded string
     * @return the public key
     * @throws DeltaClientException on error creating public key from string
     */
    public PublicKey getPublicKey(String key) throws DeltaClientException {
        try {
            byte[] byteKey = BaseEncoding.base64().decode(key);
            X509EncodedKeySpec x509PublicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePublic(x509PublicKey);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IllegalArgumentException e) {
            throw new DeltaClientException("Error getting private key from string", e);
        }
    }

    /**
     * Transforms the secret key, encoded as a base 64 string, into a secret
     * key instance.
     *
     * @param key secret key as a base64 encoded string
     * @return the secret key
     */
    public SecretKey getSymmetricKey(String key) {
        byte[] byteKey = BaseEncoding.base64().decode(key);
        return new SecretKeySpec(byteKey, 0, byteKey.length, "AES");
    }
}
