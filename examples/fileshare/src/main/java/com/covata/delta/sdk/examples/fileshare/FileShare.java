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

import com.covata.delta.sdk.DeltaClient;
import com.covata.delta.sdk.DeltaClientConfig;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.covata.delta.sdk.exception.DeltaServiceException;
import com.covata.delta.sdk.model.DeltaIdentity;
import com.covata.delta.sdk.model.DeltaSecret;
import com.google.common.collect.ImmutableMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.covata.delta.sdk.examples.fileshare.EncryptionUtil.base64ToBytes;
import static com.covata.delta.sdk.examples.fileshare.EncryptionUtil.bytesToBase64;
import static com.covata.delta.sdk.examples.fileshare.EncryptionUtil.decrypt;
import static com.covata.delta.sdk.examples.fileshare.EncryptionUtil.encrypt;
import static com.covata.delta.sdk.examples.fileshare.EncryptionUtil.generateIV;
import static com.covata.delta.sdk.examples.fileshare.EncryptionUtil.generateSecretKey;
import static com.covata.delta.sdk.examples.fileshare.EncryptionUtil.keyInBase64ToSecretKey;
import static org.apache.commons.codec.digest.DigestUtils.sha256Hex;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.apache.commons.io.FileUtils.writeByteArrayToFile;

/**
 * FileShare provides a number of abstractions to allow encryption and
 * decryption of arbitrary files, utilising Covata Delta to store and
 * exchange encryption keys with recipients of the file.
 */
public class FileShare {
    private static final Logger LOG = LoggerFactory.getLogger(FileShare.class);

    private static final String CVT = ".cvt";

    private static final int CONNECTION_TIMEOUT_SECONDS = 20;

    private final DeltaClient client;

    private DeltaIdentity identity;

    /**
     * Create a new FileShare instance linked to the given keystore
     * and pass-phrase.
     *
     * @param passPhrase  the pass-phrase for the keystore
     * @param keyStoreLoc the location of the keystore
     * @throws FileShareException on exception instantiating this instance
     */
    public FileShare(String passPhrase, String keyStoreLoc)
            throws FileShareException {
        try {
            DeltaClientConfig config = DeltaClientConfig.builder()
                    .withKeyStorePassword(passPhrase)
                    .withKeyStorePath(keyStoreLoc)
                    .withLogging(false)
                    .withConnectionTimeoutSeconds(CONNECTION_TIMEOUT_SECONDS)
                    .build();

            client = new DeltaClient(config);
            LOG.debug("Successfully created Delta client");
        } catch (DeltaClientException e) {
            throw new FileShareException("Error creating Delta client", e);
        }
    }

    /**
     * Register a new identity with Delta.
     *
     * @return the id of the new identity
     * @throws FileShareException on exception registering new identity
     */
    public String registerIdentity() throws FileShareException {
        checkIdentityNotSet();
        try {
            identity = client.createIdentity();
            LOG.debug("Identity created: {}", identity.getId());
            return identity.getId();
        } catch (DeltaClientException | DeltaServiceException e) {
            throw new FileShareException("Error registering identity", e);
        }
    }

    /**
     * Set the authenticating identity with ths FileShare instance.
     *
     * @param identityId the identity id to associate
     * @throws FileShareException on exception retrieving the given identity
     */
    public void setIdentity(String identityId) throws FileShareException {
        checkIdentityNotSet();
        try {
            identity = client.getIdentity(identityId);
        } catch (DeltaClientException | DeltaServiceException e) {
            throw new FileShareException("Error retrieving identity", e);
        }
    }

    /**
     * Encrypt the given file and create a corresponding secret in Delta.
     * The encrypted file will be created in the same directory as the
     * original file with a <i>.cvt</i> extension. The key used
     * to encrypt the secret is stored in Delta as a Secret.
     *
     * @param filename the file to be encrypted, includng the full path
     * @return the secret id of the created (base) secret
     * @throws FileShareException on exception encrypting the file and creating secret
     */
    public String encryptFile(String filename) throws FileShareException {
        checkIdentitySet();
        try {
            byte[] data = readFileToByteArray(new File(filename));
            byte[] iv = generateIV();
            SecretKey key = generateSecretKey();

            byte[] encryptedData = encrypt(data, key, iv);
            writeByteArrayToFile(new File(filename + CVT), encryptedData);

            DeltaSecret secret = identity.createSecret(bytesToBase64(key.getEncoded()));

            Map<String, String> metadata = new HashMap<>();
            metadata.put("initialisationVector", bytesToBase64(iv));
            metadata.put("sha256Hex", sha256Hex(encryptedData).toLowerCase());
            secret.synchronizeMetadata();
            secret.addMetadata(metadata);
            LOG.debug("Secret created: {}", secret.getId());
            return secret.getId();
        } catch (IOException | NoSuchAlgorithmException |
                NoSuchPaddingException | InvalidAlgorithmParameterException |
                InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | DeltaClientException |
                DeltaServiceException e) {
            throw new FileShareException("Error encrypting file", e);
        }
    }

    /**
     * Share the given secret with the given identity.
     *
     * @param secretId the secret id of the secret to share
     * @param targetId the identity id of the target identity
     * @return the secret id of the created (derived) secret
     * @throws FileShareException on exception sharing the secret
     */
    public String share(String secretId, String targetId)
            throws FileShareException {
        checkIdentitySet();
        try {
            DeltaSecret sharedSecret = identity.shareSecret(secretId, targetId);
            LOG.debug("Shared secret created: {}", sharedSecret.getId());
            return sharedSecret.getId();
        } catch (DeltaClientException | DeltaServiceException e) {
            throw new FileShareException(e);
        }
    }

    /**
     * Decrypt the given file with the secret that has the given secret id.
     *
     * @param filename the file to be decrypted, including the full path
     * @param secretId the id of the secret containing the encryption key
     * @throws FileShareException on exception decrypting the file
     */
    public void decryptFile(String filename, String secretId)
            throws FileShareException {
        checkIdentitySet();
        try {
            byte[] data = readFileToByteArray(new File(filename));

            DeltaSecret secret = identity.retrieveSecret(secretId);

            checksumMatches(data, secret.getMetadata().get("sha256Hex"));
            SecretKey key = keyInBase64ToSecretKey(secret.getContent());
            byte[] iv = base64ToBytes(secret.getMetadata().get("initialisationVector"));

            byte[] decryptedData = decrypt(data, key, iv);

            String outputName = filename.substring(0, filename.indexOf(CVT));
            writeByteArrayToFile(new File(outputName), decryptedData);

            LOG.debug("File decrypted: {}", outputName);
        } catch (IOException | DeltaClientException | DeltaServiceException |
                NoSuchAlgorithmException | InvalidKeyException |
                NoSuchPaddingException | InvalidAlgorithmParameterException |
                BadPaddingException | IllegalBlockSizeException e) {
            LOG.error("Error decrypting file with name {}", filename);
            throw new FileShareException("Error decrypting file", e);
        }
    }

    /**
     * Decrypt the given file; a secret will be retrieved based on a digest
     * of the file contents.
     *
     * @param filename the file to be decrypted, including the full path
     * @throws FileShareException on exception decrypting the file
     */
    public void decryptFile(String filename)
            throws FileShareException {
        checkIdentitySet();
        try {
            byte[] data = readFileToByteArray(new File(filename));

            List<DeltaSecret> secrets = getBaseSecretBySha256Hex(data);
            secrets = secrets.isEmpty() ? getDerivedSecretBySha256Hex(data) : secrets;

            if (secrets.isEmpty()) {
                throw new FileShareException(
                        "No secrets stored in Delta for this file");
            } else if (secrets.size() != 1) {
                throw new FileShareException(
                        "More than one secret found in Delta for this file");
            } else {
                DeltaSecret secret = secrets.get(0);
                SecretKey key = keyInBase64ToSecretKey(secret.getContent());
                byte[] iv = base64ToBytes(secret.getMetadata().get("initialisationVector"));

                byte[] decryptedData = decrypt(data, key, iv);

                String outputName = filename.substring(0, filename.indexOf(CVT));
                writeByteArrayToFile(new File(outputName), decryptedData);
                LOG.debug("File decrypted: {}", outputName);
            }
        } catch (Exception e) {
            LOG.error("Error decrypting file with name {}", filename);
            throw new FileShareException("Error decrypting file", e);
        }
    }

    private List<DeltaSecret> getBaseSecretBySha256Hex(byte[] data) {
        return client.getBaseSecretsByMetadata(identity.getId(), identity.getId(),
                ImmutableMap.of("sha256Hex", sha256Hex(data.clone()).toLowerCase()), 1, 1);
    }

    private List<DeltaSecret> getDerivedSecretBySha256Hex(byte[] data) {
        return client.getDerivedSecretsByMetadata(identity.getId(), identity.getId(),
                ImmutableMap.of("sha256Hex", sha256Hex(data.clone()).toLowerCase()), 1, 1);
    }

    private void checkIdentitySet() throws FileShareException {
        if (identity == null) {
            throw new FileShareException("An identity has already been set on this instance");
        }
    }

    private void checkIdentityNotSet() throws FileShareException {
        if (identity != null) {
            throw new FileShareException("An identity needs to be set on this instance");
        }
    }

    private void checksumMatches(byte[] data, String expected) throws FileShareException {
        String actual = sha256Hex(data).toLowerCase();
        if (!actual.equals(expected)) {
            throw new FileShareException(
                    String.format("Checksum does not match (got %s, expected %s)", actual, expected));
        }
    }
}
