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

package com.covata.delta.sdk.examples.fileshare;

import com.google.common.io.BaseEncoding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class containing helper methods useful for encrypting and
 * decrypting data.
 */
class EncryptionUtil {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static final String CRYPTO_ALGORITHM = "AES";

    private static final String RNG_ALGORITHM = "SHA1PRNG";

    /**
     * Generate a 256-bit secret key that can be used in
     * symmetric key encryption such as AES.
     *
     * @return the generated secret key
     */
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance(CRYPTO_ALGORITHM);
        keyGen.init(256, random);
        return keyGen.generateKey();
    }

    /**
     * Generate an initialisation vector that can be used in
     * symmetric key encryption such as AES.
     *
     * @return the generated initialisation vector as a byte array
     */
    public static byte[] generateIV() throws NoSuchAlgorithmException {
        SecureRandom r = SecureRandom.getInstance(RNG_ALGORITHM);
        byte[] iv = new byte[12];
        r.nextBytes(iv);
        return iv;
    }

    /**
     * Encrypt the given cipherText using the provided <code>SecretKey</code>
     * and initilization vector.
     *
     * @param plainText the plain text to encrypt
     * @param key the secret key to use for encryption
     * @param iv the initialisation vector to use for encryption
     * @return the cipher text as a byte array
     */
    static byte[] encrypt(byte[] plainText, SecretKey key, byte[] iv) throws
            NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plainText);
    }

    /**
     * Decrypt the given cipherText using the provided <code>SecretKey</code>
     * and initilization vector.
     *
     * @param cipherText the cipher text to decrypt
     * @param key the secret key to use for decryption
     * @param iv the initilization vector to use for decryption
     * @return the plain text as a byte array
     */
    public static byte[] decrypt(byte[] cipherText, SecretKey key, byte[] iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec params = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, params);

        return cipher.doFinal(cipherText);
    }

    /**
     * Convert the key encoded as a base64 string to a raw
     * <code>SecretKey</code> for AES encryption and decryption.
     *
     * @param keyInBase64 the key in base64 encoding
     * @return the key as a <code>SecretKey</code>
     */
    public static SecretKey keyInBase64ToSecretKey(String keyInBase64) {
        byte[] keyInBytes = BaseEncoding.base64().decode(keyInBase64);
        return new SecretKeySpec(keyInBytes, 0, keyInBytes.length, CRYPTO_ALGORITHM);
    }

    /**
     * Convert the given byte array to a base64 string.
     *
     * @param bytes the input as a byte array
     * @return the input in base64 encoding
     */
    public static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Convert the given base64 string to a byte array.
     *
     * @param base64 the input in base64 encoding
     * @return the input as a byte array
     */
    public static byte[] base64ToBytes(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}
