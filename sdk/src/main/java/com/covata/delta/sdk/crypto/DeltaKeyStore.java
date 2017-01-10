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
import com.covata.delta.sdk.util.DateTimeUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * This class manages interactions with an underlying key store, and provides
 * methods for interacting with private and public keys.
 * <p>
 * A Java key store is used as the underlying implementation. Using Java key
 * tools, it is possible to export and import external keys into the
 * key store.
 * </p>
 * @see <a href="http://docs.oracle.com/javase/8/docs/technotes/tools/windows/keytool.html">Java Key Tools</a>
 */
public class DeltaKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(DeltaKeyStore.class);

    private static final String KEYSTORE_TYPE = "JKS";

    private static final String ISSUER = "CN=Covata";

    private static final String SUBJECT = "CN=Delta";

    private static final int DAYS_CERTIFICATE_VALID = 30;

    private static final String ENCRYPTION_KEYS_ALIAS = "%s-encryption-keys";

    private static final String SIGNING_KEYS_ALIAS = "%s-signing-keys";

    private String keyStoreFileName;

    private String keyStoreBasePath;

    private String keyStorePassword;

    private String encryptionKeysAlias(String identityId) {
        return String.format(ENCRYPTION_KEYS_ALIAS, identityId);
    }

    private String signingKeysAlias(String identityId) {
        return String.format(SIGNING_KEYS_ALIAS, identityId);
    }

    /**
     * Constructs a key store instance by using parameters in the provided
     * configuration object.
     *
     * @param config the configuration for this key store
     */
    public DeltaKeyStore(DeltaClientConfig config) {
        this(config.getKeystoreFilename(), config.getKeyStoreBasePath(), config.getKeyStorePassword());
    }

    /**
     * Constructs a key store instance by using the provided parameters.
     *
     * @param keyStoreFileName the key store file name
     * @param keyStoreBasePath the key store base bath
     * @param keyStorePassword the password for the keystore
     */
    public DeltaKeyStore(String keyStoreFileName, String keyStoreBasePath, String keyStorePassword) {
        this.keyStoreFileName = keyStoreFileName;
        this.keyStoreBasePath = keyStoreBasePath != null ?
                keyStoreBasePath.replaceFirst("^~", System.getProperty("user.home")) : null;
        this.keyStorePassword = keyStorePassword;
    }

    /**
     * Stores the signing and encryption key pairs under a given identity id.
     *
     * @param identityId the identity id to store the key pairs under
     * @param signingKeys the signing keys to be stored
     * @param encryptionKeys the encryption keys to be stored
     * @throws DeltaClientException upon exception storing the keys
     */
    public void storeKeys(String identityId, KeyPair signingKeys, KeyPair encryptionKeys)
            throws DeltaClientException {
        boolean isExistingKeyStore = new File(keyStoreBasePath != null ?
                keyStoreBasePath + keyStoreFileName : keyStoreFileName).exists();
        try (FileInputStream is = isExistingKeyStore ? getKeyStoreInputStream() : null) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(isExistingKeyStore ? is : null,
                    isExistingKeyStore ? keyStorePassword.toCharArray() : null);

            KeyStore.ProtectionParameter protectionParameter
                    = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());

            X509Certificate signingCert = generateCertificate(signingKeys);
            KeyStore.PrivateKeyEntry signingKeyEntry
                    = new KeyStore.PrivateKeyEntry(signingKeys.getPrivate(), new Certificate[]{signingCert});
            keyStore.setEntry(signingKeysAlias(identityId), signingKeyEntry, protectionParameter);

            X509Certificate encryptionCert = generateCertificate(encryptionKeys);
            KeyStore.PrivateKeyEntry encryptionKeyEntry
                    = new KeyStore.PrivateKeyEntry(encryptionKeys.getPrivate(), new Certificate[]{encryptionCert});
            keyStore.setEntry(encryptionKeysAlias(identityId), encryptionKeyEntry, protectionParameter);

            FileOutputStream os = getKeyStoreOutputStream();
            keyStore.store(os, keyStorePassword.toCharArray());
            os.close();
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new DeltaClientException("Error storing keys into keystore", e);
        }
    }

    private FileOutputStream getKeyStoreOutputStream() throws Exception {
        return new FileOutputStream(keyStoreBasePath != null ?
                keyStoreBasePath + keyStoreFileName : keyStoreFileName);
    }

    // http://stackoverflow.com/a/11953453
    private X509Certificate generateCertificate(KeyPair keyPair) throws DeltaClientException {
        try {
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date startDate = DateTimeUtil.getCurrentDate();
            Date expiryDate = DateTimeUtil.addDays(startDate, DAYS_CERTIFICATE_VALID);
            X500Name issuer = new X500Name(ISSUER);
            X500Name subject = new X500Name(SUBJECT);

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer, serialNumber, startDate, expiryDate, subject,
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
            ContentSigner signer = builder.build(keyPair.getPrivate());


            byte[] certBytes = certBuilder.build(signer).getEncoded();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new DeltaClientException("Error generating certificate", e);
        }
    }

    /**
     * Gets the private encryption key stored under the given identity id.
     *
     * @param identityId the identity id owning the key
     * @return the private encryption key
     * @throws DeltaClientException upon exception getting the key
     */
    public PrivateKey getPrivateEncryptionKey(String identityId) throws DeltaClientException {
        return getPrivateKey(encryptionKeysAlias(identityId));
    }

    /**
     * Gets the public encryption key stored under the given identity id.
     *
     * @param identityId the identity id owning the key
     * @return the public encryption key
     * @throws DeltaClientException upon exception getting the key
     */
    public PublicKey getPublicEncryptionKey(String identityId) throws DeltaClientException {
        return getPublicKey(encryptionKeysAlias(identityId));
    }

    /**
     * Gets the private signing key stored under the given identity id.
     *
     * @param identityId the identity id owning the key
     * @return the private signing key
     * @throws DeltaClientException upon exception getting the key
     */
    public PrivateKey getPrivateSigningKey(String identityId) throws DeltaClientException {
        return getPrivateKey(signingKeysAlias(identityId));
    }

    /**
     * Gets the public signing key stored under the given identity id.
     *
     * @param identityId the identity id owning the key
     * @return the public signing key
     * @throws DeltaClientException upon exception getting the key
     */
    public PublicKey getPublicSigningKey(String identityId) throws DeltaClientException {
        return getPublicKey(signingKeysAlias(identityId));
    }

    private PrivateKey getPrivateKey(String alias) throws DeltaClientException {
        try (FileInputStream is = getKeyStoreInputStream()) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(is, keyStorePassword.toCharArray());

            KeyStore.ProtectionParameter protectionParameter
                    = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry(alias, protectionParameter);

            return privateKeyEntry.getPrivateKey();
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new DeltaClientException("Error getting private key", e);
        }
    }

    private PublicKey getPublicKey(String alias) throws DeltaClientException {
        try (FileInputStream is = getKeyStoreInputStream()) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(is, keyStorePassword.toCharArray());

            KeyStore.ProtectionParameter protectionParameter
                    = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
                    keyStore.getEntry(alias, protectionParameter);

            Certificate cert = privateKeyEntry.getCertificate();

            return (cert.getPublicKey());
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new DeltaClientException("Error getting public key", e);
        }
    }

    private FileInputStream getKeyStoreInputStream() throws FileNotFoundException {
        return new FileInputStream(keyStoreBasePath != null ? keyStoreBasePath + keyStoreFileName : keyStoreFileName);
    }

}
