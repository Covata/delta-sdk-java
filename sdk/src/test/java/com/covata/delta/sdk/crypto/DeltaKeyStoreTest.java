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

import com.covata.delta.sdk.exception.DeltaClientException;
import com.covata.delta.sdk.test.util.SharedTestKeys;
import com.google.common.io.BaseEncoding;
import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DeltaKeyStoreTest {

    private static final String KEYSTORE_FILENAME = "TestKeyStore.jks";

    private static final String KEYSTORE_PASSWORD = "KeystorePassword";

    private static final String IDENTITY_ID = "0343036e-1eef-49e8-b1fc-5b9f550d5068";

    private static KeyPair signingKeyPair = SharedTestKeys.SIGNING_KEY_PAIR;

    private static KeyPair encryptionKeyPair = SharedTestKeys.CRYPTO_KEY_PAIR;

    private DeltaKeyStore keyStore;

    private File keyStoreFile;

    @After
    public void tearDown() throws Exception {
        // some tests don't create key store file
        if (keyStoreFile != null) {
            assertTrue(keyStoreFile.delete());
        }
    }

    private String b64Encode(byte[] bytes) {
        return BaseEncoding.base64().encode(bytes);
    }

    @Test
    public void shouldCorrectlyStoreAndRetrieveKeysFromKeyStore() throws Exception {
        keyStore = new DeltaKeyStore(KEYSTORE_FILENAME, null, KEYSTORE_PASSWORD);
        keyStore.storeKeys(IDENTITY_ID, signingKeyPair, encryptionKeyPair);

        PrivateKey retrievedPrivateKey = keyStore.getPrivateSigningKey(IDENTITY_ID);
        assertNotNull(retrievedPrivateKey);
        assertEquals(b64Encode(signingKeyPair.getPrivate().getEncoded()),
                b64Encode(retrievedPrivateKey.getEncoded()));
        PublicKey retrievedPublicKey = keyStore.getPublicSigningKey(IDENTITY_ID);
        assertNotNull(retrievedPublicKey);
        assertEquals(b64Encode(signingKeyPair.getPublic().getEncoded()),
                b64Encode(retrievedPublicKey.getEncoded()));

        retrievedPrivateKey = keyStore.getPrivateEncryptionKey(IDENTITY_ID);
        assertNotNull(retrievedPrivateKey);
        assertEquals(b64Encode(encryptionKeyPair.getPrivate().getEncoded()),
                b64Encode(retrievedPrivateKey.getEncoded()));
        retrievedPublicKey = keyStore.getPublicEncryptionKey(IDENTITY_ID);
        assertNotNull(retrievedPublicKey);
        assertEquals(b64Encode(encryptionKeyPair.getPublic().getEncoded()),
                b64Encode(retrievedPublicKey.getEncoded()));

        keyStoreFile = new File(KEYSTORE_FILENAME);
        assertTrue(keyStoreFile.isFile());
    }

    @Test
    public void shouldCorrectlyCreateKeyStoreAtSpecifiedLocation() throws Exception {
        String path = System.getProperty("user.dir") + "/src/test";
        keyStore = new DeltaKeyStore(KEYSTORE_FILENAME, path, KEYSTORE_PASSWORD);

        keyStore.storeKeys(IDENTITY_ID, signingKeyPair, encryptionKeyPair);

        File file = new File(path + KEYSTORE_FILENAME);
        assertTrue(file.exists());
        assertFalse(file.isDirectory());

        keyStoreFile = new File(path + KEYSTORE_FILENAME);
        assertTrue(keyStoreFile.isFile());
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionGettingPublicKeyWhenKeyStoreNotPresent() throws Exception {
        DeltaKeyStore keyStore = new DeltaKeyStore(KEYSTORE_FILENAME, "file does not exist", KEYSTORE_PASSWORD);
        keyStore.getPublicSigningKey(IDENTITY_ID);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionGettingPrivateKeyWhenKeyStoreNotPresent() throws Exception {
        DeltaKeyStore keyStore = new DeltaKeyStore(KEYSTORE_FILENAME, "file does not exist", KEYSTORE_PASSWORD);
        keyStore.getPrivateSigningKey(IDENTITY_ID);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionStoringKeysWhenSigningKeysNotProvided() throws Exception {
        DeltaKeyStore keyStore = new DeltaKeyStore(KEYSTORE_FILENAME, "file does not exist", KEYSTORE_PASSWORD);
        keyStore.storeKeys(IDENTITY_ID, null, encryptionKeyPair);
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionStoringKeysWhenEncryptionKeysNotProvided() throws Exception {
        DeltaKeyStore keyStore = new DeltaKeyStore(KEYSTORE_FILENAME, "file does not exist", KEYSTORE_PASSWORD);
        keyStore.storeKeys(IDENTITY_ID, signingKeyPair, null);
    }

}
