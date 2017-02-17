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
import com.covata.delta.sdk.exception.DeltaClientException;
import com.covata.delta.sdk.exception.DeltaServiceException;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

import java.io.File;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static com.google.common.base.Suppliers.memoizeWithExpiration;

/**
 * An instance of this class encapsulates an <i>identity</i> in Covata Delta.
 * An identity can be a user, application, device or any other identifiable
 * entity that can create secrets and/or be target recipient of a secret.
 * <p>
 * A <code>DeltaIdentity</code> has two sets of asymmetric keys, for
 * encryption and for signing of requests. Identities may also have optional
 * <i>public</i>, searchable metadata and a reference to an identifier in an
 * external system.
 * </p>
 */
public class DeltaIdentity {

    private static final long UNKNOWN_METADATA_VERSION = 0L;

    private static final int EXPIRATION_SECONDS = 60;

    private final Instant initialized;

    private final DeltaClient parent;

    private final String id;

    private final String externalId;

    private final String signingPublicKey;

    private final String encryptionPublicKey;

    private volatile Supplier<Map<String, String>> metadataSupplier;

    private volatile Long version;

    private DeltaIdentity(DeltaIdentityBuilder builder) {
        this.parent = builder.parent;
        this.initialized = Instant.now();

        this.id = builder.id;
        this.externalId = builder.externalId;
        this.signingPublicKey = builder.signingPublicKey;
        this.encryptionPublicKey = builder.encryptionPublicKey;
        this.metadataSupplier = builder.metadata != null ?
                memoizeWithExpiration(() -> getMetadataFromRemote(builder.metadata), EXPIRATION_SECONDS, TimeUnit.SECONDS)::get :
                memoizeWithExpiration(this::getMetadataFromRemote, EXPIRATION_SECONDS, TimeUnit.SECONDS)::get;
        this.version = builder.version;
    }

    public String getId() {
        return id;
    }

    public String getExternalId() {
        return externalId;
    }

    public String getSigningPublicKeyBase64() {
        return signingPublicKey;
    }

    public String getEncryptionPublicKeyBase64() {
        return encryptionPublicKey;
    }

    /**
     * Synchronizes the metadata of this identity with the one in server.
     *
     * @throws DeltaServiceException upon service exception
     */
    public void synchronizeMetadata() throws DeltaServiceException {
        DeltaIdentity response = parent.getIdentity(id);
        version = response.getVersion();
        metadataSupplier = memoizeWithExpiration(() -> getMetadataFromRemote(response.getMetadata()),
                EXPIRATION_SECONDS, TimeUnit.SECONDS)::get;
    }

    public Map<String, String> getMetadata() {
        return metadataSupplier.get();
    }

    private Map<String, String> getMetadataFromRemote() throws DeltaServiceException {
        return parent.getIdentity(id).getMetadata();
    }

    private Map<String, String> getMetadataFromRemote(Map<String, String> initialValue) throws DeltaServiceException {
        return Instant.now().isBefore(initialized.plus(EXPIRATION_SECONDS, ChronoUnit.SECONDS)) ?
                initialValue : getMetadataFromRemote();
    }

    /**
     * Adds the given key and value pair as metadata for this identity. If the
     * metadata previously contained a mapping for the key, the old value
     * is replaced by the specified value. An attempt to
     * update metadata with outdated version will be rejected by the server.
     * Both metadata and metadata version of this identity will be synchronized
     * immediately after execution.
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
     * Adds the key and value pairs in the provided map as metadata
     * for this identity. If the metadata previously contained a mapping
     * for the key, the old value is replaced by the specified value. An attempt
     * to update metadata with outdated version will be rejected by the server.
     * Both metadata and metadata version of this identity will be synchronized
     * immediately after execution.
     *
     * @param metadata the metadata to add to this identity
     * @throws DeltaServiceException upon service exception
     */
    public void addMetadata(Map<String, String> metadata)
            throws DeltaServiceException {
        try {
            parent.addIdentityMetadata(id, version, metadata);
        } finally {
            synchronizeMetadata();
        }
    }

    /**
     * Removes metadata from the given identity by key. An attempt to
     * update metadata with outdated version will be rejected by the server.
     * Both metadata and metadata version of this identity will be synchronized
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
     * Removes metadata from the given identity by key. An attempt to
     * update metadata with outdated version will be rejected by the server.
     * Both metadata and metadata version of this identity will be synchronized
     * immediately after execution.
     *
     * @param keys a collection of keys with which the specified key-value pairs
     *             are to be removed
     * @throws DeltaServiceException upon service exception
     */
    public void removeMetadata(Collection<String> keys)
            throws DeltaServiceException {
        try {
            parent.removeIdentityMetadata(id, version, keys);
        } finally {
            synchronizeMetadata();
        }
    }

    /**
     * Retrieves the version of this {@code DeltaIdentity}.
     * Modification to metadata will increment the version number.
     *
     * @return the version number associated with the metadata of this identity
     */
    public Long getVersion() {
        return version;
    }

    /**
     * Retrieves an identity with this identity.
     *
     * @param identityId the identity to retrieve
     * @return the identity
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaIdentity retrieveIdentity(String identityId)
            throws DeltaClientException, DeltaServiceException {
        return parent.getIdentity(this.id, identityId);
    }

    /**
     * Creates a new secret in Delta with the given byte contents.
     *
     * @param contents the contents of the secret
     * @return the secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret createSecret(byte[] contents)
            throws DeltaClientException, DeltaServiceException {
        return parent.createSecret(this.id, contents);
    }

    /**
     * Creates a new secret in Delta with the given string contents.
     *
     * @param contents the contents of the secret
     * @return the secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret createSecret(String contents)
            throws DeltaClientException, DeltaServiceException {
       return parent.createSecret(this.id, contents);
    }

    /**
     * Creates a new secret in Delta with the given file contents.
     *
     * @param contents the contents of the secret
     * @return the secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret createSecret(File contents)
            throws DeltaClientException, DeltaServiceException {
        return parent.createSecret(this.id, contents);
    }

    /**
     * Shares a secret with the target identity.
     *
     * @param secretId the secret id
     * @param targetId the identity id of the recipient
     * @return the derived secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret shareSecret(String secretId, String targetId)
            throws DeltaClientException, DeltaServiceException {
        return parent.shareSecret(this.id, targetId, secretId);
    }

    /**
     * Retrieves a secret with this identity.
     *
     * @param secretId the secret id
     * @return the secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret retrieveSecret(String secretId)
            throws DeltaClientException, DeltaServiceException {
        return parent.getSecret(this.id, secretId);
    }

    /**
     * Gets a list of secrets matching the given metadata key and value pairs,
     * bound by the pagination parameters.
     *
     * @param metadata the metadata of interest
     * @param page the page number
     * @param pageSize the maximum number of items contained in a page
     * @return a list of secrets
     */
    public List<DeltaSecret> retrieveDerivedSecrets(Map<String, String> metadata,
                                                    int page, int pageSize) {
        return parent.getDerivedSecretsByMetadata(
                this.id, this.id, metadata, page, pageSize);
    }

    /**
     * Gets a list of secrets shared with this identity bound by the pagination
     * parameters.
     *
     * @param page the page number
     * @param pageSize the maximum number of items contained in a page
     * @return a list of secrets
     */
    public List<DeltaSecret> retrieveSecretsSharedWithMe(int page, int pageSize) {
        return parent.getSecretsSharedWithMe(this.id, page, pageSize);
    }

    /**
     * Gets back a builder for a new <code>DeltaIdentity</code>. The parent
     * is the <code>DeltaClient</code> this identity will use to call
     * further API methods.
     *
     * @param parent the parent <code>DeltaClient</code> for internal API calls
     * @return a new builder for a single <code>DeltaIdentity</code>
     */
    public static DeltaIdentityBuilder builder(DeltaClient parent) {
        return new DeltaIdentityBuilder(parent);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("id", id)
                .add("externalId", externalId)
                .add("signingPublicKey", signingPublicKey)
                .add("encryptionPublicKey", encryptionPublicKey)
                .add("version", version)
                .toString();
    }

    /**
     * Builder class for <code>DeltaIdentity</code>. This builder should be
     * used to transform responses from the Delta service into
     * <code>DeltaIdentity</code> objects. It should not be used explicitly
     * to create new <code>DeltaIdentity</code>.
     */
    public static final class DeltaIdentityBuilder {

        private final DeltaClient parent;

        private String id;

        private String externalId;

        private String signingPublicKey;

        private String encryptionPublicKey;

        private Map<String, String> metadata;

        private long version = UNKNOWN_METADATA_VERSION;

        private DeltaIdentityBuilder(DeltaClient parent) {
            this.parent = parent;
        }

        public DeltaIdentityBuilder withId(String id) {
            this.id = id;
            return this;
        }

        public DeltaIdentityBuilder withExternalId(String externalId) {
            this.externalId = externalId;
            return this;
        }

        public DeltaIdentityBuilder withSigningPublicKey(String signingPublicKey) {
            this.signingPublicKey = signingPublicKey;
            return this;
        }

        public DeltaIdentityBuilder withEncryptionPublicKey(String encryptionPublicKey) {
            this.encryptionPublicKey = encryptionPublicKey;
            return this;
        }

        public DeltaIdentityBuilder withMetadata(Map<String, String> metadata) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.putAll(metadata);
            return this;
        }

        public DeltaIdentityBuilder withVersion(long version) {
            this.version = version;
            return this;
        }

        public DeltaIdentity build() {
            return new DeltaIdentity(this);
        }
    }

}
