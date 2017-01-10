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

package com.covata.delta.sdk;

import com.covata.delta.sdk.api.DeltaApiClient;
import com.covata.delta.sdk.api.request.CreateIdentityRequest;
import com.covata.delta.sdk.api.request.CreateSecretRequest;
import com.covata.delta.sdk.api.request.GetBaseSecretsByMetadataRequest;
import com.covata.delta.sdk.api.request.GetDerivedSecretsByMetadataRequest;
import com.covata.delta.sdk.api.request.GetDerivedSecretsRequest;
import com.covata.delta.sdk.api.request.GetEventsRequest;
import com.covata.delta.sdk.api.request.GetIdentitiesByMetadataRequest;
import com.covata.delta.sdk.api.request.GetIdentityRequest;
import com.covata.delta.sdk.api.request.GetSecretsRequest;
import com.covata.delta.sdk.api.request.SecretRequest;
import com.covata.delta.sdk.api.request.ShareSecretRequest;
import com.covata.delta.sdk.api.request.UpdateIdentityMetadataRequest;
import com.covata.delta.sdk.api.request.UpdateSecretMetadataRequest;
import com.covata.delta.sdk.api.response.CreateIdentityResponse;
import com.covata.delta.sdk.api.response.CreateSecretResponse;
import com.covata.delta.sdk.api.response.GetEventResponse;
import com.covata.delta.sdk.api.response.GetIdentityResponse;
import com.covata.delta.sdk.api.response.GetSecretMetadataResponse;
import com.covata.delta.sdk.api.response.GetSecretResponse;
import com.covata.delta.sdk.api.response.GetSecretsResponse;
import com.covata.delta.sdk.api.response.ShareSecretResponse;
import com.covata.delta.sdk.crypto.DeltaKeyStore;
import com.covata.delta.sdk.crypto.CryptoService;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.covata.delta.sdk.exception.DeltaServiceException;
import com.covata.delta.sdk.model.DeltaEvent;
import com.covata.delta.sdk.model.DeltaIdentity;
import com.covata.delta.sdk.model.DeltaSecret;
import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The main entry point for the Delta SDK.
 * <p>
 * An instance of this class will provide an interface to work and interact
 * with the Delta API. The core domain objects (<code>DeltaIdentity</code>,
 * <code>DeltaSecret</code> and <code>DeltaEvent</code>) are returned from
 * method calls to this class, and themselves provide fluent interface that
 * can be used to continue interactive with the DeltaAPI. Consumers of this
 * SDK can therefore choose whether they wish to construct all the calls from
 * base values (i.e. id strings such as identityId, secretId, etc) or via the
 * fluent interfaces (or a mixture of both).
 * </p>
 *
 */
public class DeltaClient {

    private final DeltaApiClient apiClient;

    private final DeltaClientConfig config;

    private final DeltaKeyStore keyStore;

    private final CryptoService cryptoService;

    /**
     * Creates a new DeltaClient instance from the provided configuration.
     *
     * @param config {@link DeltaClientConfig} the configuration for the client
     * @throws DeltaClientException upon exception
     */
    public DeltaClient(DeltaClientConfig config) throws DeltaClientException {
        this.config = config;
        this.keyStore = config.getKeyStore();
        this.apiClient = config.getApiClient();
        this.cryptoService = config.getCryptoService();
    }

    /**
     * Creates a new identity in Delta.
     *
     * @return the identity
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaIdentity createIdentity()
            throws DeltaClientException, DeltaServiceException {
        return createIdentity(null, Collections.emptyMap());
    }

    /**
     * Creates a new identity in Delta with the provided metadata and
     * external id.
     *
     * @param externalId the external id to associate with the identity
     * @param metadata the metadata to associate with the identity
     * @return the identity
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaIdentity createIdentity(String externalId, Map<String, String> metadata)
            throws DeltaClientException, DeltaServiceException {
        KeyPair signingKeys = cryptoService.generatePublicPrivateKey();
        String signingPublicKey = BaseEncoding.base64().encode(signingKeys.getPublic().getEncoded());
        KeyPair encryptionKeys = cryptoService.generatePublicPrivateKey();
        String encryptionPublicKey = BaseEncoding.base64().encode(encryptionKeys.getPublic().getEncoded());

        CreateIdentityResponse response = apiClient.createIdentity(
                CreateIdentityRequest.builder(signingPublicKey, encryptionPublicKey)
                        .withMetadata(metadata)
                        .withExternalId(externalId)
                        .build());

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(this)
                .withId(response.getIdentityId())
                .withEncryptionPublicKey(encryptionPublicKey)
                .withSigningPublicKey(signingPublicKey)
                .withExternalId(externalId)
                .withMetadata(metadata)
                .build();

        keyStore.storeKeys(deltaIdentity.getId(), signingKeys, encryptionKeys);

        return deltaIdentity;
    }

    /**
     * Gets the identity matching the given identity id.
     *
     * @param identityId the authenticating identity id
     * @param identityIdToRetrieve the identity to retrieve
     * @return the identity
     * @throws DeltaClientException  upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaIdentity getIdentity(String identityId, String identityIdToRetrieve)
            throws DeltaClientException, DeltaServiceException {
        checkId(identityId);
        checkId(identityIdToRetrieve);

        GetIdentityResponse response = apiClient
                .getIdentity(new GetIdentityRequest(identityId, identityIdToRetrieve));

        return DeltaIdentity.builder(this)
                .withId(response.getId())
                .withExternalId(response.getExternalId())
                .withEncryptionPublicKey(response.getEncryptionPublicKey())
                .withMetadata(response.getMetadata())
                .withVersion(response.getVersion())
                .build();
    }

    /**
     * Gets the identity matching the given identity id.
     *
     * @param identityId the authenticating identity id
     * @return the identity
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaIdentity getIdentity(String identityId)
            throws DeltaClientException, DeltaServiceException {
        return getIdentity(identityId, identityId);
    }

    /**
     * Creates a new secret in Delta with the given string contents.
     *
     * @param identityId the authenticating identity id
     * @param contents the contents of the secret
     * @return the secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret createSecret(String identityId, String contents)
            throws DeltaClientException, DeltaServiceException {
        return createSecret(identityId, contents.getBytes(config.getEncodingCharset()));
    }

    /**
     * Creates a new secret in Delta with the given file contents.
     *
     * @param identityId the authenticating identity id
     * @param contents the contents of the secret
     * @return the secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret createSecret(String identityId, File contents)
            throws DeltaClientException, DeltaServiceException {
        checkLength(contents.length());

        byte[] inputBytes;
        try (FileInputStream inputStream = new FileInputStream(contents)) {
            inputBytes = new byte[(int) contents.length()];
            inputStream.read(inputBytes);
        } catch (IOException e) {
            throw new DeltaClientException("Error reading file", e);
        }

        return createSecret(identityId, inputBytes);
    }

    /**
     * Creates a new secret in Delta with the given byte contents.
     *
     * @param identityId the authenticating identity id
     * @param contents the contents of the secret
     * @return the secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret createSecret(String identityId, byte[] contents)
            throws DeltaClientException, DeltaServiceException {
        checkLength(contents.length);

        SecretKey key = cryptoService.generateSecretKey();
        byte[] iv = cryptoService.generateInitialisationVector();

        String contentsBase64 = cryptoService.encrypt(contents, key, iv);
        String encryptedKey = cryptoService.encryptKeyWithPublicKey(key,
                keyStore.getPublicEncryptionKey(identityId));

        CreateSecretResponse createSecretResponse = apiClient.createSecret(
                CreateSecretRequest.builder(identityId)
                        .withContent(contentsBase64)
                        .withEncryptionDetails(encryptedKey, iv)
                        .build());

        return getSecret(identityId, createSecretResponse.getSecretId());
    }

    /**
     * Gets the given secret by id.
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @return the secret
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret getSecret(String identityId, String secretId)
            throws DeltaServiceException {
        SecretRequest request = new SecretRequest(identityId, secretId);

        GetSecretResponse response = apiClient.getSecret(request);

        return DeltaSecret.builder(this, cryptoService)
                .withId(response.getId())
                .withRsaKeyOwnerId(response.getRsaKeyOwner())
                .withCreatedBy(response.getCreatedBy())
                .withCreated(response.getCreated())
                .withModified(response.getModified())
                .withSymmetricKey(response.getEncryptionDetails().getSymmetricKey())
                .withInitialisationVector(response.getEncryptionDetails().getInitialisationVector())
                .withDerived(response.isDerived())
                .build();
    }

    /**
     * Gets the plaintext content, given the symmetric key
     * and initialisation vector used for encryption.
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @param symmetricKey the symmetric key used for encryption
     * @param initialisationVector the initialisation vector
     * @return the plaintext content
     * @throws DeltaServiceException upon server-side exception
     * @throws DeltaClientException upon client-side exception
     */
    public String getSecretContent(String identityId,
                                   String secretId,
                                   String symmetricKey,
                                   String initialisationVector)
            throws DeltaServiceException, DeltaClientException {
        String encryptedContent = getSecretContentEncrypted(identityId, secretId);
        String keyString = cryptoService.decryptWithPrivateKey(
            symmetricKey,
            keyStore.getPrivateEncryptionKey(identityId));
        return cryptoService.decrypt(
                BaseEncoding.base64().decode(encryptedContent),
                cryptoService.getSymmetricKey(keyString),
                BaseEncoding.base64().decode(initialisationVector));
    }

    /**
     * Gets the encrypted content given the secret id.
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @return the encrypted content
     * @throws DeltaServiceException upon service exception
     */
    public String getSecretContentEncrypted(String identityId, String secretId)
            throws DeltaServiceException {
        SecretRequest request = new SecretRequest(identityId, secretId);
        return apiClient.getSecretContent(request);
    }

    /**
     * Gets the metadata key and value pairs for the given secret.
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @return a map of metadata key and value pairs for the secret
     * @throws DeltaServiceException upon exception
     */
    public GetSecretMetadataResponse getSecretMetadata(String identityId, String secretId)
            throws DeltaServiceException {
        return apiClient.getSecretMetadata(new SecretRequest(identityId, secretId));
    }

    /**
     * Adds metadata to the given secret. The version number is required for
     * optimistic locking on concurrent updates. An attempt to
     * update metadata with outdated version will be rejected by the server.
     * <p>
     * The latest metadata version can be obtained from the server and is
     * stored in the {@link GetSecretMetadataResponse} object. The code snippet
     * below shows an attempt to synchronize the version number of a secret
     * with the server prior to updating its metadata.
     * </p>
     * <pre>
     * {@code
     * GetSecretMetadataResponse currentMetadata = deltaClient.getSecretMetadata(identityId, secretId);
     * long version = currentMetadata.getVersion();
     *
     * deltaClient.addSecretMetadata(identityId, secretId, version, additionalMetadata)
     * }
     * </pre>
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @param version the version number of the metadata being updated
     * @param metadata a map of metadata key and value pairs
     * @throws DeltaServiceException upon service exception
     */
    public void addSecretMetadata(String identityId, String secretId,
                                  long version, Map<String, String> metadata)
            throws DeltaServiceException {
        checkId(identityId);
        checkId(secretId);

        GetSecretMetadataResponse secretMetadata = getSecretMetadata(identityId, secretId);
        Map<String, String> metadataMap = new HashMap<>(secretMetadata.getMetadata());
        metadataMap.putAll(metadata);

        apiClient.updateSecretMetadata(UpdateSecretMetadataRequest.builder(identityId)
                .withSecretId(secretId)
                .withVersion(version)
                .withMetadata(metadataMap)
                .build());
    }

    /**
     * Removes metadata from the given secret by key. The version number is
     * required for optimistic locking on concurrent updates. An attempt to
     * update metadata with outdated version will be rejected by the server.
     * <p>
     * The latest metadata version can be obtained from the server and is
     * stored in the {@link GetSecretMetadataResponse} object. The code snippet
     * below shows an attempt to synchronize the version number of a secret
     * with the server prior to updating its metadata.
     * </p>
     * <pre>
     * {@code
     * GetSecretMetadataResponse currentMetadata = deltaClient.getSecretMetadata(identityId, secretId);
     * long version = currentMetadata.getVersion();
     *
     * deltaClient.removeSecretMetadata(identityId, secretId, version, keysToRemove)
     * }
     * </pre>
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @param version the version number of the metadata being updated
     * @param keys a collection of keys with which the specified key-value pairs
     *             are to be removed
     * @throws DeltaServiceException upon service exception
     */
    public void removeSecretMetadata(String identityId, String secretId,
                                     long version, Collection<String> keys)
            throws DeltaServiceException {
        checkId(identityId);
        checkId(secretId);

        GetSecretMetadataResponse secretMetadata = getSecretMetadata(identityId, secretId);
        Map<String, String> metadataMap = new HashMap<>(secretMetadata.getMetadata());
        metadataMap.keySet().removeAll(keys);

        apiClient.updateSecretMetadata(UpdateSecretMetadataRequest.builder(identityId)
                .withSecretId(secretId)
                .withVersion(version)
                .withMetadata(metadataMap)
                .build());
    }

    /**
     * Adds metadata to the given identity. The version number is required for
     * optimistic locking on concurrent updates. An attempt to
     * update metadata with outdated version will be rejected by the server.
     * <p>
     * The latest metadata version can be obtained from the server and is
     * stored in the {@link DeltaIdentity} or {@link GetIdentityResponse} object.
     * The code snippet below shows an attempt to synchronize the version number
     * of an identity with the server prior to updating its metadata.
     * </p>
     * <pre>
     * {@code
     * DeltaIdentity currentIdentity = deltaClient.getIdentity(identityId);
     * long version = currentIdentity.getVersion();
     *
     * deltaClient.addIdentityMetadata(identityId, version, additionalMetadata)
     * }
     * </pre>
     *
     * @param identityId the authenticating identity id
     * @param version the version number of the metadata being updated
     * @param metadata a map of metadata key and value pairs
     * @throws DeltaServiceException upon service exception
     */
    public void addIdentityMetadata(String identityId, long version, Map<String, String> metadata)
            throws DeltaServiceException {
        checkId(identityId);

        DeltaIdentity identity = getIdentity(identityId);
        Map<String, String> metadataMap = new HashMap<>(identity.getMetadata());
        metadataMap.putAll(metadata);

        apiClient.updateIdentityMetadata(UpdateIdentityMetadataRequest.builder(identityId)
                .withIdentityIdToUpdate(identityId)
                .withVersion(version)
                .withMetadata(metadataMap)
                .build());
    }

    /**
     * Removes metadata from the given identity by key. The version number is
     * required for optimistic locking on concurrent updates. An attempt to
     * update metadata with outdated version will be rejected by the server.
     *
     * <p> The latest metadata version can be obtained from the server and is
     * stored in the {@link DeltaIdentity} or {@link GetIdentityResponse} object.
     * The code snippet below shows an attempt to synchronize the version number
     * of an identity with the server prior to updating its metadata.</p>
     *
     * <pre>
     * {@code
     * DeltaIdentity currentIdentity = deltaClient.getIdentity(identityId);
     * long version = currentIdentity.getVersion();
     *
     * deltaClient.removeIdentityMetadata(identityId, version, keysToRemove)
     * }
     * </pre>
     *
     * @param identityId the authenticating identity id
     * @param version the version number of the metadata being updated
     * @param keys a collection of keys with which the specified key-value pairs
     *             are to be removed
     * @throws DeltaServiceException upon service exception
     */
    public void removeIdentityMetadata(String identityId, long version, Collection<String> keys)
            throws DeltaServiceException {
        checkId(identityId);

        DeltaIdentity identity = getIdentity(identityId);
        Map<String, String> metadataMap = new HashMap<>(identity.getMetadata());
        metadataMap.keySet().removeAll(keys);

        apiClient.updateIdentityMetadata(UpdateIdentityMetadataRequest.builder(identityId)
                .withIdentityIdToUpdate(identityId)
                .withVersion(version)
                .withMetadata(metadataMap)
                .build());
    }


    /**
     * Shares the base secret with the specified recipient. The
     * contents will be encrypted with the public encryption key of the
     * RSA key owner, and a new secret key and initialisation vector
     * will be generated. This call will result in a new derived secret
     * being created and returned.
     *
     * @param identityId the authenticating identity id
     * @param recipientId the target identity id to share the base secret
     * @param secretId the base secret id
     * @return the derived secret
     * @throws DeltaClientException upon client-side exception
     * @throws DeltaServiceException upon service exception
     */
    public DeltaSecret shareSecret(String identityId, String recipientId, String secretId)
            throws DeltaClientException, DeltaServiceException {
        checkId(identityId);
        checkId(recipientId);
        checkId(secretId);

        DeltaIdentity recipient = getIdentity(identityId, recipientId);

        DeltaSecret secret = getSecret(identityId, secretId);

        SecretKey key = cryptoService.generateSecretKey();
        byte[] iv = cryptoService.generateInitialisationVector();
        String contentsBase64 = cryptoService.encrypt(secret.getContent(), key, iv);
        String encryptedKey = cryptoService.encryptKeyWithPublicKey(key,
                cryptoService.getPublicKey(recipient.getEncryptionPublicKeyBase64()));
        ShareSecretResponse response =
                apiClient.shareSecret(ShareSecretRequest.builder(identityId)
                        .withBaseSecret(secretId)
                        .withRsaKeyOwnerId(recipientId)
                        .withContent(contentsBase64)
                        .withEncryptionDetails(encryptedKey, iv)
                        .build());

        return DeltaSecret.builder(this, cryptoService)
                .withId(response.getSecretId())
                .withRsaKeyOwnerId(recipientId)
                .withCreatedBy(identityId)
                .withSymmetricKey(encryptedKey)
                .withInitialisationVector(BaseEncoding.base64().encode(iv))
                .withBaseSecret(secretId)
                .withDerived(true)
                .build();
    }


    /**
     * Deletes the secret with the given secret id.
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @throws DeltaServiceException upon exception
     */
    public void deleteSecret(String identityId, String secretId)
            throws DeltaServiceException {
        checkId(identityId);
        checkId(secretId);

        apiClient.deleteSecret(new SecretRequest(identityId, secretId));
    }

    /**
     * Gets a list of events associated with the given secret id .
     *
     * @param identityId the authenticating identity id
     * @param secretId the secret id
     * @return a list of events
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaEvent> getEventsBySecretId(String identityId, String secretId)
            throws DeltaServiceException {
        checkId(identityId);
        checkId(secretId);

        return createEventsList(apiClient.getEvents(GetEventsRequest
                .builder(identityId)
                .withSecretId(secretId)
                .build()));
    }

    /**
     * Gets a list of events associated with the given RSA key owner id.
     *
     * @param identityId the authenticating identity id
     * @param rsaKeyOwnerId the RSA key owner
     * @return a list of events
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaEvent> getEventsByRsaKeyOwner(String identityId, String rsaKeyOwnerId)
            throws DeltaServiceException {
        checkId(identityId);
        checkId(rsaKeyOwnerId);

        return createEventsList(apiClient.getEvents(GetEventsRequest.builder(identityId)
                .withRsaKeyOwner(rsaKeyOwnerId)
                .build()));
    }

    private List<DeltaEvent> createEventsList(List<GetEventResponse> eventsResponse) {
        return eventsResponse.stream()
                .map(eventResponse -> {
                    GetEventResponse.EventDetails detailsResponse = eventResponse.getEventDetails();
                    return new DeltaEvent.DeltaEventBuilder()
                            .withId(eventResponse.getId())
                            .withSourceIp(eventResponse.getSourceIp())
                            .withTimestamp(eventResponse.getTimestamp())
                            .withEventName(eventResponse.getType())
                            .withHost(eventResponse.getHost())
                            .withBaseSecretId(detailsResponse.getBaseSecretId())
                            .withSecretId(detailsResponse.getSecretId())
                            .withRequesterId(detailsResponse.getRequesterId())
                            .withSecretCreatorId(detailsResponse.getSecretOwnerId())
                            .withRsaKeyOwnerId(detailsResponse.getRsaKeyOwnerId())
                            .build();
                })
                .collect(Collectors.toList());
    }

    private void checkId(String id) throws IllegalArgumentException {
        if (Strings.isNullOrEmpty(id)) {
            throw new IllegalArgumentException("Id cannot be null or empty");
        }
        if (!id.matches("^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$")) {
            throw new IllegalArgumentException(String.format("Invalid id: %s", id));
        }
    }

    private void checkLength(long length) throws DeltaClientException {
        if (length > config.getMaxSecretSizeBytesBase64()) {
            throw new DeltaClientException("Data must not be greater than " +
                    (config.getMaxSecretSizeBytesBase64() / 1000) + "KiB");
        }
    }

    /**
     * Gets a list of secrets derived from the base secret, bound
     * by the pagination parameters.
     *
     * @param identityId the authenticating identity id
     * @param baseSecretId the base secret id
     * @param page the page number
     * @param pageSize the page size
     * @return a list of derived secrets satisfying the request
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaSecret> getDerivedSecretByBaseSecret(String identityId, String baseSecretId,
                                                          int page, int pageSize)
            throws DeltaServiceException {
        checkId(identityId);
        checkId(baseSecretId);

        return createSecretsList(apiClient.getDerivedSecrets(GetDerivedSecretsRequest
                .builder(identityId)
                .withSecretId(baseSecretId)
                .withPage(page)
                .withPageSize(pageSize)
                .build()), SecretType.DERIVED);
    }

    private List<DeltaSecret> createSecretsList(List<GetSecretsResponse> secretsResponse, SecretType secretType) {
        return secretsResponse.stream()
                .map(secretResponse -> DeltaSecret.builder(this, cryptoService)
                        .withId(secretResponse.getId())
                        .withCreatedBy(secretResponse.getCreatedBy())
                        .withRsaKeyOwnerId(secretResponse.getRsaKeyOwner())
                        .withCreated(secretResponse.getCreated())
                        .withBaseSecret(secretResponse.getBaseSecret())
                        .withMetadata(secretResponse.getMetadata())
                        .withDerived(secretType == SecretType.DERIVED)
                        .build())
                .collect(Collectors.toList());
    }

    /**
     * Gets a list of identities matching the given metadata key and value pairs,
     * bound by the pagination parameters.
     *
     * @param identityId the authenticating identity id
     * @param metadata the metadata key and value pairs to filter
     * @param page the page number
     * @param pageSize the page size
     * @return a list of identities satisfying the request
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaIdentity> getIdentitiesByMetadata(String identityId, Map<String, String> metadata,
                                                       int page, int pageSize)
            throws DeltaServiceException {
        checkId(identityId);

        List<GetIdentityResponse> identitiesResponse =
                apiClient.getIdentitiesByMetadata(GetIdentitiesByMetadataRequest.builder(identityId)
                        .withMetadata(metadata)
                        .withPage(page)
                        .withPageSize(pageSize)
                        .build());

        return createIdentitiesList(identitiesResponse);
    }

    private List<DeltaIdentity> createIdentitiesList(List<GetIdentityResponse> identitiesResponse) {
        return identitiesResponse.stream()
                .map(identityResponse -> DeltaIdentity.builder(this)
                        .withId(identityResponse.getId())
                        .withEncryptionPublicKey(identityResponse.getEncryptionPublicKey())
                        .withMetadata(identityResponse.getMetadata())
                        .withExternalId(identityResponse.getExternalId())
                        .withVersion(identityResponse.getVersion())
                        .build())
                .collect(Collectors.toList());
    }


    /**
     * Updates the metadata for the given identity.
     *
     * @param identityId the authenticating identity id
     * @param identityIdToUpdate the id of the identity being updated
     * @param version the version of the identity being updated
     * @param metadata the metadata key and value pairs to update
     * @throws DeltaServiceException upon exception
     */

    public void updateIdentityMetadata(String identityId, String identityIdToUpdate,
                                          long version, Map<String, String> metadata)
            throws DeltaServiceException {
        checkId(identityId);
        checkId(identityIdToUpdate);

        apiClient.updateIdentityMetadata(UpdateIdentityMetadataRequest.builder(identityId)
                .withIdentityIdToUpdate(identityIdToUpdate)
                .withVersion(version)
                .withMetadata(metadata)
                .build());
    }

    /**
     * Gets a list of base secrets matching the given creator and metadata key
     * and value pairs, bound by the pagination parameters.
     *
     * @param identityId the authenticating identity id
     * @param createdBy the creator to filer
     * @param metadata the metadata key and value pairs to filter
     * @param page the page number
     * @param pageSize the page size
     * @return a list of secrets satisfying the request
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaSecret> getBaseSecretsByMetadata(String identityId,
                                                      String createdBy,
                                                      Map<String, String> metadata,
                                                      int page,
                                                      int pageSize)
            throws DeltaServiceException {
        checkId(identityId);

        List<GetSecretsResponse> secretsResponse =
                apiClient.getBaseSecretsByMetadata(GetBaseSecretsByMetadataRequest.builder(identityId)
                        .withCreatedBy(createdBy)
                        .withMetadata(metadata)
                        .withPage(page)
                        .withPageSize(pageSize)
                        .build());

        return createSecretsList(secretsResponse, SecretType.BASE);
    }

    /**
     * Gets a list of derived secrets matching the given RSA key owner and
     * metadata key and value pairs, bound by the pagination parameters.
     *
     * @param identityId the authenticating identity id
     * @param rsaKeyOwnerId the RSA key owner to filter
     * @param metadata the metadata key and value pairs to filter
     * @param page the page number
     * @param pageSize the page size
     * @return a list of secrets satisfying the request
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaSecret> getDerivedSecretsByMetadata(String identityId,
                                                         String rsaKeyOwnerId,
                                                         Map<String, String> metadata,
                                                         int page,
                                                         int pageSize)
            throws DeltaServiceException {
        checkId(identityId);

        List<GetSecretsResponse> secretsResponse =
                apiClient.getDerivedSecretsByMetadata(GetDerivedSecretsByMetadataRequest.builder(identityId)
                        .withRsaKeyOwnerId(rsaKeyOwnerId)
                        .withMetadata(metadata)
                        .withPage(page)
                        .withPageSize(pageSize)
                        .build());

        return createSecretsList(secretsResponse, SecretType.DERIVED);
    }

    /**
     * Gets a list of secrets shared by the given identity bound by the
     * pagination parameters.
     *
     * @param identityId the authenticating identity id
     * @param page the page number
     * @param pageSize the page size
     * @return a list of secrets satisfying the request
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaSecret> getSharedSecrets(String identityId, int page, int pageSize)
            throws DeltaServiceException {
        checkId(identityId);

        List<GetSecretsResponse> secretsResponse =
                apiClient.getSharedSecrets(GetSecretsRequest.builder(identityId)
                        .withPage(page)
                        .withPageSize(pageSize)
                        .build());

        return createSecretsList(secretsResponse, SecretType.DERIVED);
    }

    /**
     * Gets a list of secrets shared with the given identity bound by the
     * pagination parameters.
     *
     * @param identityId the authenticating identity id
     * @param page the page number
     * @param pageSize the page size
     * @return a list of secrets satisfying the request
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaSecret> getSecretsSharedWithMe(String identityId, int page, int pageSize)
            throws DeltaServiceException {
        checkId(identityId);

        List<GetSecretsResponse> secretsResponse =
                apiClient.getSecretsSharedWithMe(GetSecretsRequest.builder(identityId)
                        .withPage(page)
                        .withPageSize(pageSize)
                        .build());

        return createSecretsList(secretsResponse, SecretType.DERIVED);
    }

    /**
     * Gets a list of secrets owned by the given identity bound by the
     * pagination parameters.
     *
     * @param identityId the authenticating identity id
     * @param page the page number
     * @param pageSize the page size
     * @return a list of secrets satisfying the request
     * @throws DeltaServiceException upon exception
     */
    public List<DeltaSecret> getOwnedSecrets(String identityId, int page, int pageSize)
            throws DeltaServiceException {
        checkId(identityId);

        List<GetSecretsResponse> secretsResponse =
                apiClient.getOwnedSecrets(GetSecretsRequest.builder(identityId)
                        .withPage(page)
                        .withPageSize(pageSize)
                        .build());

        return createSecretsList(secretsResponse, SecretType.BASE);
    }
    
    private static enum SecretType {
        BASE, DERIVED
    }

}
