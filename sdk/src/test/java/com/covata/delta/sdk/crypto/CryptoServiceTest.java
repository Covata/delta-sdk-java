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
import com.covata.delta.sdk.api.DeltaApiClient;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.google.common.io.BaseEncoding;
import org.junit.After;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import static com.covata.delta.sdk.test.util.SharedTestKeys.CRYPTO_KEY_PAIR;
import static com.covata.delta.sdk.test.util.SharedTestKeys.SECRET_KEY_A;
import static com.covata.delta.sdk.test.util.SharedTestKeys.SECRET_KEY_B;
import static com.covata.delta.sdk.test.util.SharedTestKeys.SIGNING_KEY_PAIR;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CryptoServiceTest {

    private static DeltaKeyStore mockKeyStore = mock(DeltaKeyStore.class);

    private static final String MOCK_API_URL = "https://test.com/v1/";

    private static DeltaClientConfig config = DeltaClientConfig.builder()
            .withApiUrl(MOCK_API_URL)
            .withApiClient(mock(DeltaApiClient.class))
            .withKeyStore(mockKeyStore)
            .build();

    private static CryptoService cryptoService = config.getCryptoService();

    private static final Logger LOG = LoggerFactory.getLogger(CryptoServiceTest.class);

    private static final Charset ENCODING_CHARSET = Charset.forName("UTF-8");

    private static final String FILE_NAME = "test.txt";

    private static final String IDENTITY_ID = UUID.randomUUID().toString();

    @After
    public void tearDown() {
        File file = new File(FILE_NAME);
        if (file.exists()) {
            assertTrue(file.delete());
        }
    }

    @Test
    public void shouldEncryptAndDecryptTextCorrectly() throws Exception {
        String plainText = "Kontrast - Sean Tyas";
        byte[] iv = cryptoService.generateInitialisationVector();
        String encrypted = cryptoService.encrypt(plainText, SECRET_KEY_A, iv);
        assertNotNull(encrypted);

        byte[] base64CipherText = BaseEncoding.base64().decode(encrypted);
        assertEquals(36, base64CipherText.length);
        String decrypted = cryptoService.decrypt(base64CipherText, SECRET_KEY_A, iv);
        assertNotNull(decrypted);
        assertEquals(plainText, decrypted);
    }

    @Test
    public void shouldEncryptAndDecryptFileCorrectly() throws Exception {
        File file = new File(FILE_NAME);
        assertTrue(file.createNewFile());
        String string = "Hello World\r\nGood Bye! Yolo!";
        try (FileOutputStream os = new FileOutputStream(file, false)) {
            os.write(string.getBytes(ENCODING_CHARSET));
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new Exception();
        }

        byte[] iv = cryptoService.generateInitialisationVector();
        String encrypted = cryptoService.encrypt(file, SECRET_KEY_A, iv);
        assertNotNull(encrypted);

        byte[] base64CipherText = BaseEncoding.base64().decode(encrypted);
        assertEquals(44, base64CipherText.length);
        String decrypted = cryptoService.decrypt(base64CipherText, SECRET_KEY_A, iv);
        assertNotNull(decrypted);
        assertEquals(string, decrypted);
    }

    @Test
    public void shouldEncryptAndDecryptSymmetricKeyCorrectly() throws Exception {
        String expectedSecretKey = BaseEncoding.base64().encode(SECRET_KEY_A.getEncoded());
        String encryptedSecretKey = cryptoService.encryptKeyWithPublicKey(SECRET_KEY_A, CRYPTO_KEY_PAIR.getPublic());
        String actualSecretKey = cryptoService.decryptWithPrivateKey(encryptedSecretKey, CRYPTO_KEY_PAIR.getPrivate());
        assertEquals(expectedSecretKey, actualSecretKey);
    }

    @Test
    public void shouldDecryptStringWhenGivenTheEncryptedKey() throws Exception {
        String plainText = "Kontrast - Sean Tyas";

        byte[] iv = cryptoService.generateInitialisationVector();
        String encrypted = cryptoService.encrypt(plainText, SECRET_KEY_A, iv);
        String encryptedSecretKey = cryptoService.encryptKeyWithPublicKey(SECRET_KEY_A, CRYPTO_KEY_PAIR.getPublic());
        when(mockKeyStore.getPrivateEncryptionKey(eq(IDENTITY_ID))).thenReturn(CRYPTO_KEY_PAIR.getPrivate());

        String decrypted = cryptoService.decrypt(encrypted, encryptedSecretKey, iv, IDENTITY_ID);
        assertEquals(plainText, decrypted);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionGivenInvalidEncryptionKey() throws Exception {
        String plainText = "Until we meet again - Ben Nicky";

        byte[] iv = cryptoService.generateInitialisationVector();
        cryptoService.encrypt(plainText, null, iv);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionDecryptedStringGivenInvalidCipherText() throws Exception {
        String plainText = "Degeneration 2016";
        byte[] iv = cryptoService.generateInitialisationVector();
        String encrypted = cryptoService.encrypt(plainText, SECRET_KEY_A, iv) + "RaNd0M";

        cryptoService.decrypt(encrypted.getBytes(ENCODING_CHARSET), SECRET_KEY_A, iv);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionDecryptedStringGivenInvalidPrivateKey() throws Exception {
        String plainText = "Alien - Intro Mix ASOT";
        byte[] iv = cryptoService.generateInitialisationVector();
        String encrypted = cryptoService.encrypt(plainText, SECRET_KEY_A, iv);
        assertNotNull(encrypted);

        byte[] base64CipherText = BaseEncoding.base64().decode(encrypted);
        assertEquals(38, base64CipherText.length);
        cryptoService.decrypt(base64CipherText, SECRET_KEY_B, iv);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenEncryptKeyWithPublicKeyWithNullSecretKey() throws Exception {
        cryptoService.encryptKeyWithPublicKey(null, CRYPTO_KEY_PAIR.getPublic());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenEncryptKeyWithPublicKeyWithNullPublicKey() throws Exception {
        cryptoService.encryptKeyWithPublicKey(SECRET_KEY_A, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenDecryptWithPrivateKeyWithNullSecretKey() throws Exception {
        cryptoService.decryptWithPrivateKey(null, CRYPTO_KEY_PAIR.getPrivate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenDecryptWithPrivateKeyWithNullPublicKey() throws Exception {
        cryptoService.decryptWithPrivateKey("cyphertext", null);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowDeltaExceptionOnDecryptionError() throws Exception {
        String encryptedSecretKey = cryptoService.encryptKeyWithPublicKey(SECRET_KEY_A, CRYPTO_KEY_PAIR.getPublic());
        cryptoService.decryptWithPrivateKey(encryptedSecretKey, SIGNING_KEY_PAIR.getPrivate());
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowDeltaExceptionWhenEncryptingWithInvalidKey() throws Exception {
        cryptoService.encrypt(new byte[]{}, new SecretKeySpec(new byte[]{1}, ""), new byte[]{});
    }

    @Test
    public void shouldReturnCorrectPrivateKeyGivenValidPrivateKeyString() throws Exception {
        String privKeyString = BaseEncoding.base64().encode(CRYPTO_KEY_PAIR.getPrivate().getEncoded());

        PrivateKey privateKey = cryptoService.getPrivateKey(privKeyString);
        assertEquals(CRYPTO_KEY_PAIR.getPrivate(), privateKey);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionGivenInvalidPrivateKeyString() throws Exception {
        cryptoService.getPrivateKey("Rumble in the jungle");
    }

    @Test
    public void shouldReturnCorrectPublicKeyGivenValidPublicKeyString() throws Exception {
        String pubKeyString = BaseEncoding.base64().encode(CRYPTO_KEY_PAIR.getPublic().getEncoded());

        PublicKey publicKey = cryptoService.getPublicKey(pubKeyString);
        assertEquals(CRYPTO_KEY_PAIR.getPublic(), publicKey);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionGivenInvalidPublicKeyString() throws Exception {
        cryptoService.getPublicKey("ZaToX");
    }

}
