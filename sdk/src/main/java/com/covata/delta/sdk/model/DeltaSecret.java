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
package com.covata.delta.sdk.model;

import com.covata.delta.sdk.DeltaClient;
import com.covata.delta.sdk.api.response.GetSecretMetadataResponse;
import com.covata.delta.sdk.crypto.CryptoService;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.covata.delta.sdk.exception.DeltaServiceException;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.BaseEncoding;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static com.google.common.base.Suppliers.memoize;
import static com.google.common.base.Suppliers.memoizeWithExpiration;

/**
 * An instance of this class encapsulates a <i>secret</i> in Covata Delta.
 * A secret has contents, which is encrypted by a symmetric key algorithm as
 * defined in the immutable <code>DeltaSecret.EncryptionDetails</code>, holding
 * information such as the symmetric (secret) key, initialisation vector and
 * algorithm. The symmetric key is encrypted with the public encryption key
 * of the RSA key owner. This class will return the decrypted contents and
 * symmetric key if returned as a result of <code>DeltaClient</code>.
 */
public class DeltaSecret {

    private static final long UNKNOWN_METADATA_VERSION = 0L;

    private static final int EXPIRATION_SECONDS = 60;

    private final Instant initialized;

    private final DeltaClient parent;

    private final CryptoService cryptoService;

    private final String id;

    private final String createdBy;

    private final String rsaKeyOwnerId;

    private final String created;

    private final String modified;

    private final Supplier<String> encryptedContentSupplier =
            memoize(this::getContentFromRemote)::get;

    private volatile Supplier<Map<String, String>> metadataSupplier;

    private volatile Long metadataVersion;

    private final Supplier<EncryptionDetails> encryptionDetailsSupplier;

    private final boolean derived;

    private final String baseSecret;

    private DeltaSecret(final DeltaSecretBuilder builder) {
        this.parent = builder.parent;
        this.cryptoService = builder.cryptoService;
        this.id = builder.id;
        this.createdBy = builder.createdBy;
        this.rsaKeyOwnerId = builder.rsaKeyOwnerId;
        this.created = builder.created;
        this.modified = builder.modified;
        this.derived = builder.derived;
        this.baseSecret = builder.baseSecret;

        this.initialized = Instant.now();

        this.encryptionDetailsSupplier = canBuildEncryptionDetails(builder) ?
                memoize(() -> new EncryptionDetails(builder))::get :
                memoize(this::getEncryptionDetailsFromRemote)::get;

        this.metadataSupplier = builder.metadata != null ?
                memoizeWithExpiration(() -> getMetadataFromRemote(builder.metadata), EXPIRATION_SECONDS, TimeUnit.SECONDS)::get :
                memoizeWithExpiration(this::getMetadataFromRemote, EXPIRATION_SECONDS, TimeUnit.SECONDS)::get;
        this.metadataVersion = builder.metadataVersion;
    }

    private boolean canBuildEncryptionDetails(final DeltaSecretBuilder builder) {
        return builder.initialisationVector != null && builder.symmetricKey != null;
    }

    public String getId() {
        return id;
    }

    /**
     * Gets the identity id of the creator and owner of the secret. The creator
     * can be different to the RSA key owner (in the case of derived secrets)
     * but a base secret and all derived secrets will have the same creator.
     *
     * @return the identity id of the creator
     */
    public String getCreatedBy() {
        return createdBy;
    }

    /**
     * Gets the identity id of the identity whose public key has been used to
     * encrypt the key protecting the secret content.
     *
     * @return the identity id of the RSA key owner
     */
    public String getRsaKeyOwnerId() {
        return rsaKeyOwnerId;
    }

    /**
     * Gets the created date of the secret in ISO 8601 format. This date is set
     * upon creation of the secret by the service and is immutable.
     *
     * @return the created date of the secret in ISO 8601 format
     */
    public String getCreatedDate() {
        return created;
    }

    /**
     * Gets the modified date of the secret in ISO 8601 format. This date is
     * changed each time metadata is updated for a secret (there are no
     * other mutable fields of a secret).
     *
     * @return the modified date of the secret in ISO 8601 format
     */
    public String getModifiedDate() {
        return modified;
    }

    /**
     * Gets the content of a secret, encrypted with the details defined in the
     * <code>EncryptionDetails</code> of this secret and encoded in base64.
     *
     * @return the content of the secret encoded in base64
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public String getContent()
            throws DeltaClientException, DeltaServiceException {
        String encryptedContent = encryptedContentSupplier.get();
        String encryptedKey = getEncryptionDetails().getSymmetricKey();
        byte[] iv = BaseEncoding.base64().decode(
                getEncryptionDetails().getInitialisationVector());
        return cryptoService
                .decrypt(encryptedContent, encryptedKey, iv, rsaKeyOwnerId);
    }

    private String getContentFromRemote() throws DeltaServiceException {
        return parent.getSecretContentEncrypted(rsaKeyOwnerId, id);
    }

    private EncryptionDetails getEncryptionDetailsFromRemote() throws DeltaServiceException {
        return parent.getSecret(rsaKeyOwnerId, id).getEncryptionDetails();
    }


    /**
     * Gets the metadata for this secret. Metadata are key-value pairs
     * of strings that can be added to a secret to facilitate description
     * and lookup. Secrets can support any number of metadata elements,
     * but each key or value has a limit of 256 characters.
     * The cache for metadata is refreshed every 60 seconds. This means the
     * first call made to <code>getMetadata</code> after 60 seconds
     * will trigger a server request.
     *
     * @return the metadata for this secret
     * @throws DeltaServiceException upon service exception
     */
    public Map<String, String> getMetadata() throws DeltaServiceException {
        return metadataSupplier.get();
    }

    /**
     * Synchronizes the metadata of this secret with the one in server.
     *
     * @throws DeltaServiceException upon service exception
     */
    public void synchronizeMetadata() throws DeltaServiceException {
        GetSecretMetadataResponse response = parent.getSecretMetadata(rsaKeyOwnerId, id);
        metadataVersion = response.getVersion();
        metadataSupplier = memoizeWithExpiration(() -> getMetadataFromRemote(response.getMetadata()),
                EXPIRATION_SECONDS, TimeUnit.SECONDS)::get;
    }

    private Map<String, String> getMetadataFromRemote() throws DeltaServiceException {
        return parent.getSecretMetadata(rsaKeyOwnerId, id).getMetadata();
    }

    private Map<String, String> getMetadataFromRemote(Map<String, String> initialValue) throws DeltaServiceException {
        return Instant.now().isBefore(initialized.plus(EXPIRATION_SECONDS, ChronoUnit.SECONDS)) ?
            initialValue : getMetadataFromRemote();
    }

    /**
     * Gets the encryption details used to encrypt this secret.
     *
     * @return encryption details
     */
    public EncryptionDetails getEncryptionDetails() {
        return encryptionDetailsSupplier.get();
    }

    /**
     * Returns true if this secret is derived from a base secret. Derived
     * secrets are created in Covata Delta when a secret owner shares a secret
     * they own with another identity.
     *
     * @return true if this secret has been derived from another secret
     */
    public boolean isDerived() {
        return derived;
    }

    /**
     * Returns the base secret id if this secret is derived, otherwise it will
     * return null. Derived secrets are created in Covata Delta when a secret
     * owner shares a secret they own with another identity.
     *
     * @return the base secret id
     */
    public String getBaseSecretId() {
        return baseSecret;
    }

    /**
     * Adds the given key and value pair as metadata for this secret. If the
     * metadata previously contained a mapping for the key, the old value
     * is replaced by the specified value. An attempt to update metadata with
     * outdated version will be rejected by the server. Both metadata and
     * metadata version of this secret will be synchronized immediately after
     * execution.
     *
     * @param name the name with which the specified value is to be associated
     * @param value the value to be associated with the specified name
     * @throws DeltaServiceException upon service exception
     */
    public void addMetadata(String name, String value)
            throws DeltaServiceException {
        this.addMetadata(ImmutableMap.of(name, value));
    }

    /**
     * Adds the key and value pairs in the provided map as metadata for this
     * secret. If the metadata previously contained a mapping for the key, the
     * old value is replaced by the specified value. An attempt to update
     * metadata with outdated version will be rejected by the server. Both
     * metadata and metadata version of this secret will be synchronized
     * immediately after execution.
     *
     * @param metadata the metadata to add to this secret
     * @throws DeltaServiceException upon service exception
     */
    public void addMetadata(Map<String, String> metadata)
            throws DeltaServiceException {
        try {
            parent.addSecretMetadata(rsaKeyOwnerId, this.id, metadataVersion, metadata);
        } finally {
            synchronizeMetadata();
        }
    }

    /**
     * Removes metadata from the given secret by key. An attempt to update
     * metadata with outdated version will be rejected by the server. Both
     * metadata and metadata version of this secret will be synchronized
     * immediately after execution.
     *
     * @param keys an array of keys with which the specified key-value pairs
     *             are to be removed
     * @throws DeltaServiceException upon service exception
     */
    public void removeMetadata(String... keys)
            throws DeltaServiceException {
        this.removeMetadata(Arrays.asList(keys));
    }

    /**
     * Removes metadata from the given secret by key. An attempt to update
     * metadata with outdated version will be rejected by the server. Both
     * metadata and metadata version of this secret will be synchronized
     * immediately after execution.
     *
     * @param keys a collection of keys with which the specified key-value pairs
     *             are to be removed
     * @throws DeltaServiceException upon service exception
     */
    public void removeMetadata(Collection<String> keys)
            throws DeltaServiceException {
        try {
            parent.removeSecretMetadata(rsaKeyOwnerId, this.id, metadataVersion, keys);
        } finally {
            synchronizeMetadata();
        }
    }

    /**
     * Shares this secret with the target recipient identity. This action
     * will create a new (derived) secret in Covata Delta, and the new
     * secret will be returned to the caller.
     *
     * The credentials of the RSA key owner must be present in the local
     * key store, otherwise a <code>DeltaClientException</code> will be
     * thrown.
     *
     * @param identityId the recipient identity id
     * @return the new shared (derived) secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret shareWith(String identityId)
            throws DeltaClientException, DeltaServiceException {
        return parent.shareSecret(rsaKeyOwnerId, identityId, this.id);
    }

    /**
     * Shares this secret with the target recipient identity. This action
     * will create a new (derived) secret in Covata Delta, and the new
     * secret will be returned to the caller.
     *
     * The credentials of the RSA key owner must be present in the local
     * key store, otherwise a <code>DeltaClientException</code> will be
     * thrown.
     *
     * @param identity the recipient identity
     * @return the new shared (derived) secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret shareWith(DeltaIdentity identity)
            throws DeltaClientException, DeltaServiceException {
        return parent.shareSecret(rsaKeyOwnerId, identity.getId(), this.id);
    }

    /**
     * Gets a list of audited events associated with this secret.
     *
     * The credentials of the RSA key owner must be present in the local
     * key store, otherwise a <code>DeltaClientException</code> will be
     * thrown.
     *
     * @return a list of audited events associated with this secret
     * @throws DeltaServiceException upon service exception
     */
    public List<DeltaEvent> getEvents() throws DeltaServiceException {
        return parent.getEventsBySecretId(rsaKeyOwnerId, this.id);
    }

    /**
     * Gets a list of secrets derived from this one, based on the pagination
     * parameters.
     * <p>
     * The credentials of the RSA key owner must be present in the local
     * key store, otherwise a <code>DeltaClientException</code> will be
     * thrown.
     * </p>
     * @param page the page number
     * @param pageSize the page size
     * @return a list of derived secrets associated with this secret
     * @throws DeltaServiceException upon service exception
     */
    public List<DeltaSecret> getDerivedSecrets(int page, int pageSize)
            throws DeltaServiceException {
        return parent.getDerivedSecretByBaseSecret(
                rsaKeyOwnerId, this.id, page, pageSize);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("id", id)
                .add("createdBy", createdBy)
                .add("rsaKeyOwnerId", rsaKeyOwnerId)
                .add("created", created)
                .add("modified", modified)
                .add("baseSecret", baseSecret)
                .add("derived", derived)
                .add("metadataVersion", metadataVersion)
                .toString();
    }

    /**
     * Gets back a builder for a new <code>DeltaSecret</code>. The parent
     * is the <code>DeltaClient</code> this secret will use to call
     * further API methods.
     *
     * @param parent the parent <code>DeltaClient</code> for internal API calls
     * @param cryptoService the crypto service to be used by this <code>DeltaSecret</code>
     * @return a new builder for a single <code>DeltaSecret</code>
     */
    public static DeltaSecretBuilder builder(DeltaClient parent, CryptoService cryptoService) {
        return new DeltaSecretBuilder(parent, cryptoService);
    }

    public static class EncryptionDetails {

        private final String symmetricKey;

        private final String algorithm;

        private final int keySize;

        private final String initialisationVector;

        private final String modeOfOperation;

        private final String paddingScheme;

        private EncryptionDetails(final DeltaSecretBuilder builder) {
            this.symmetricKey = builder.symmetricKey;
            this.algorithm = builder.algorithm;
            this.keySize = builder.keySize;
            this.initialisationVector = builder.initialisationVector;
            this.modeOfOperation = builder.modeOfOperation;
            this.paddingScheme = builder.paddingScheme;
        }

        /**
         * Gets the symmetric key as a base64 encoded string. The symmetric
         * key is used to encryption of the content of this secret.
         *
         * @return the symmetric key as a base64 encoded string
         */
        public String getSymmetricKey() {
            return symmetricKey;
        }

        /**
         * Gets the initialisation vector base64 encoded string.
         * The initilization vector is used to encryption of the content
         * of this secret.
         *
         * @return the initialisation vector as a base64 encoded string
         */
        public String getInitialisationVector() {
            return initialisationVector;
        }

        /**
         * Gets the encryption algorithm used to encrypt the content of
         * this secret.
         *
         * @return the encryption algorithm
         */
        public String getAlgorithm() {
            return algorithm;
        }

        /**
         * Gets the size (in bits) of the symmetric key.
         *
         * @return the size of the symmetric key
         */
        public int getKeySize() {
            return keySize;
        }

        /**
         * Gets the mode of operation of the encryption algorithm used to
         * encrypt the content of this secret.
         *
         * @return the mode of operation of the encryption algorithm
         */
        public String getModeOfOperation() {
            return modeOfOperation;
        }

        /**
         * Gets the padding scheme used to encrypt the content of this secret.
         *
         * @return the padding scheme
         */
        public String getPaddingScheme() {
            return paddingScheme;
        }
    }

    /**
     * Builder class for <code>DeltaSecret</code>. This builder should be
     * used to transform responses from the Delta service into
     * <code>DeltaSecret</code> objects. It should not be used explicitly
     * to create new <code>DeltaSecret</code>.
     */
    public static final class DeltaSecretBuilder {

        private final DeltaClient parent;

        private final CryptoService cryptoService;

        private String id;

        private String createdBy;

        private String rsaKeyOwnerId;

        private String created;

        private String modified;

        private Map<String, String> metadata;

        private String symmetricKey;

        private String algorithm;

        private int keySize;

        private String initialisationVector;

        private String modeOfOperation;

        private String paddingScheme;

        private boolean derived;

        private String baseSecret;

        private long metadataVersion = UNKNOWN_METADATA_VERSION;

        private DeltaSecretBuilder(DeltaClient parent, CryptoService cryptoService) {
            this.parent = parent;
            this.cryptoService = cryptoService;
        }

        public DeltaSecretBuilder withId(String id) {
            this.id = id;
            return this;
        }

        public DeltaSecretBuilder withCreatedBy(String createdBy) {
            this.createdBy = createdBy;
            return this;
        }

        public DeltaSecretBuilder withRsaKeyOwnerId(String rsaKeyOwnerId) {
            this.rsaKeyOwnerId = rsaKeyOwnerId;
            return this;
        }

        public DeltaSecretBuilder withCreated(String created) {
            this.created = created;
            return this;
        }

        public DeltaSecretBuilder withModified(String modified) {
            this.modified = modified;
            return this;
        }

        public DeltaSecretBuilder withMetadata(Map<String, String> metadata) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.putAll(metadata);
            return this;
        }

        public DeltaSecretBuilder withSymmetricKey(String symmetricKey) {
            this.symmetricKey = symmetricKey;
            return this;
        }

        public DeltaSecretBuilder withInitialisationVector(String initialisationVector) {
            this.initialisationVector = initialisationVector;
            return this;
        }

        public DeltaSecretBuilder withDerived(boolean derived) {
            this.derived = derived;
            return this;
        }

        public DeltaSecretBuilder withBaseSecret(String baseSecret) {
            this.baseSecret = baseSecret;
            return this;
        }

        public DeltaSecretBuilder withAlgorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public DeltaSecretBuilder withKeySize(int keySize) {
            this.keySize = keySize;
            return this;
        }

        public DeltaSecretBuilder withModeOfOperation(String modeOfOperation) {
            this.modeOfOperation = modeOfOperation;
            return this;
        }

        public DeltaSecretBuilder withPaddingScheme(String paddingScheme) {
            this.paddingScheme = paddingScheme;
            return this;
        }

        public DeltaSecretBuilder withMetadataVersion(long metadataVersion) {
            this.metadataVersion = metadataVersion;
            return this;
        }

        public DeltaSecret build() {
            return new DeltaSecret(this);
        }

    }

}
