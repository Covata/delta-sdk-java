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
package com.covata.delta.sdk.api;

import com.covata.delta.sdk.DeltaClientConfig;
import com.covata.delta.sdk.api.interceptor.AuthorizationInterceptor;
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
import com.covata.delta.sdk.exception.DeltaClientException;
import com.covata.delta.sdk.exception.DeltaServiceException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.net.HttpHeaders;
import okhttp3.CipherSuite;
import okhttp3.ConnectionSpec;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.ResponseBody;
import okhttp3.TlsVersion;
import okhttp3.logging.HttpLoggingInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import java.io.IOException;
import java.net.ProtocolException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static java.lang.String.format;
import static okhttp3.logging.HttpLoggingInterceptor.Level.BASIC;
import static okhttp3.logging.HttpLoggingInterceptor.Level.NONE;

/**
 * The Delta API Client is an abstraction over the Delta API for execution of
 * requests and transformation of responses into POJOs.
 */
public class DeltaApiClient {

    private static final Logger LOG = LoggerFactory.getLogger(DeltaApiClient.class);

    private final DeltaApi deltaApi;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private static final Interceptor NETWORK_INTERCEPTOR =
            chain -> {
                okhttp3.Response response;
                try {
                    response = chain.proceed(chain.request());
                } catch (ProtocolException e) {
                    // Return a place holder response in event of a protocol exception
                    // See also: http://stackoverflow.com/a/35145921
                    response = new okhttp3.Response.Builder()
                            .request(chain.request())
                            .body(ResponseBody.create(MediaType.parse("application/json; charset=UTF-8"), "{}"))
                            .code(204)
                            .protocol(Protocol.HTTP_1_1)
                            .build();
                }
                return response;
            };

    DeltaApiClient(final DeltaApi deltaApi) {
        this.deltaApi = deltaApi;
    }

    /**
     * Constructs a new Delta API client with the given configuration and
     * initialised <code>DeltaKeyStore</code>.
     *
     * @param config   the Delta client configuration
     * @param keyStore the Delta key store
     * @throws DeltaClientException upon exception
     */
    public DeltaApiClient(final DeltaClientConfig config, final DeltaKeyStore keyStore) throws DeltaClientException {
        this(config, keyStore, null);
    }

    /**
     * Constructs a new Delta API client with the given configuration,
     * initialised <code>DeltaKeyStore</code> and {@link okhttp3.ConnectionSpec}.
     *
     * @param config the Delta client configuration
     * @param keyStore the Delta key store
     * @param connectionSpec the {@link okhttp3.ConnectionSpec}
     * @throws DeltaClientException upon exception
     */
    public DeltaApiClient(final DeltaClientConfig config,
                          final DeltaKeyStore keyStore,
                          ConnectionSpec connectionSpec)
            throws DeltaClientException {
        checkArgument(!isNullOrEmpty(config.getApiUrl()), "DELTA_API_URL environment variable not set or empty.");

        ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_2)
                .cipherSuites(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
                .build();

        OkHttpClient client = new OkHttpClient.Builder()
                .connectionSpecs(connectionSpec != null ?
                        Arrays.asList(spec, connectionSpec) : Collections.singletonList(spec))
                .addNetworkInterceptor(new HttpLoggingInterceptor()
                        .setLevel(config.isLoggingEnabled() ? BASIC : NONE))
                .addNetworkInterceptor(NETWORK_INTERCEPTOR)
                .addInterceptor(new AuthorizationInterceptor(keyStore))
                .connectTimeout(config.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                .writeTimeout(config.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                .readTimeout(config.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                .build();

        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(config.getApiUrl())
                .addConverterFactory(JacksonConverterFactory.create(OBJECT_MAPPER))
                .client(client)
                .build();

        deltaApi = retrofit.create(DeltaApi.class);
    }

    /**
     * Checks if the response is valid. Wrap the status code and throw
     * a <code>DeltaServiceException</code> if unsuccessful.
     *
     * @param response the response to check
     * @param errorMessage the message to use in the exception
     * @throws DeltaServiceException upon service exception
     */
    private void checkResponse(Response<?> response, String errorMessage)
            throws DeltaServiceException {
        if (!response.isSuccessful()) {
            switch (response.code()) {
                case 400:
                    throw new DeltaServiceException("Bad Request");
                case 401:
                    throw new DeltaServiceException("Unauthorized");
                case 403:
                    throw new DeltaServiceException("Forbidden");
                case 404:
                    throw new DeltaServiceException("Not Found");
                case 412:
                    throw new DeltaServiceException("Precondition Failed");
                case 500:
                    throw new DeltaServiceException("Internal Server Error");
                default:
                    throw new DeltaServiceException(errorMessage);
            }
        }
    }

    /**
     * Execution wrapper that executes the given call in OkHttp and either
     * return a response if successful or an exception if Delta service
     * returned an error.
     *
     * @param call the OkHttp call to execute
     * @param errorMessage exception message to use if an exception occurs
     * @param <T> the response expected from the call
     * @return the response extracted from the response body
     * @throws DeltaServiceException upon service exception
     */
    private <T> T executeCallAndReturnResponse(Call<T> call, String errorMessage)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(call, Response::body, errorMessage);
    }


    /**
     * Execution wrapper that executes the given call in OkHttp and either
     * return a response if successful or an exception if Delta service
     * returned an error.
     *
     * @param call the OkHttp call to execute
     * @param transformationFunction the function to transform the http Response
     *                               to ResponseObject
     * @param errorMessage exception message to use if an exception occurs
     * @param <T> the response expected from the call
     * @param <R> the response object
     * @return the response after applying transformation
     * @throws DeltaServiceException upon service exception
     */
    private <T, R> R executeCallAndReturnResponse(Call<T> call,
                                                  Function<Response<T>, R> transformationFunction,
                                                  String errorMessage)
            throws DeltaServiceException {
        try {
            Response<T> response = call.execute();
            checkResponse(response, errorMessage);
            return transformationFunction.apply(response);
        } catch (IOException e) {
            LOG.error(e.getMessage());
            throw new DeltaServiceException(errorMessage, e);
        }
    }


    /**
     * Creates a new identity in Delta.
     *
     * @param request the identity creation request
     * @return the identity response
     * @throws DeltaServiceException upon service exception
     */
    public CreateIdentityResponse createIdentity(CreateIdentityRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.createIdentity(request), "Error creating identity");
    }

    /**
     * Gets the identity matching the given identity id.
     *
     * @param request the identity retrieval request
     * @return the identity response
     * @throws DeltaServiceException upon service exception
     */
    public GetIdentityResponse getIdentity(GetIdentityRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getIdentity(request.getIdentityId(), request.getIdentityIdToRetrieve()),
                format("Error getting identity %s", request.getIdentityIdToRetrieve()));
    }

    /**
     * Creates a new secret in Delta. The key used for encryption should
     * be encrypted with the key of the authenticating identity.
     *
     * @param request the secret creation request
     * @return the secret response of the new derived secret
     * @throws DeltaServiceException upon service exception
     */
    public CreateSecretResponse createSecret(CreateSecretRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.createSecret(request.getIdentityId(), request),
                format("Error creating secret for identity %s", request.getIdentityId()));
    }

    /**
     * Gets the given secret. This does not include the metadata and contents,
     * they need to be made as separate requests, <code>getSecretMetadata</code>
     * and <code>getSecretContent</code> respectively.
     *
     * @param request the secret retrieval request
     * @return the secret response
     * @throws DeltaServiceException upon service exception
     */
    public GetSecretResponse getSecret(SecretRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getSecret(request.getIdentityId(), request.getSecretId()),
                format("Error getting secret %s", request.getSecretId()));
    }

    /**
     * Gets the contents of the given secret.
     *
     * @param request the secret retrieval request
     * @return the contents of the secret
     * @throws DeltaServiceException upon service exception
     */
    public String getSecretContent(SecretRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getSecretContent(request.getIdentityId(), request.getSecretId()),
                format("Error getting content for secret %s", request.getSecretId()));
    }

    /**
     * Gets the metadata key and value pairs for the given secret.
     *
     * @param request the secret retrieval request
     * @return a map of metadata key and value pairs for the secret
     * @throws DeltaServiceException upon service exception
     */
    public GetSecretMetadataResponse getSecretMetadata(SecretRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getSecretMetadata(request.getIdentityId(), request.getSecretId()),
                r -> new GetSecretMetadataResponse(
                        r.body(),
                        Long.parseUnsignedLong(r.headers().get(HttpHeaders.ETAG))),
                format("Error getting metadata for secret %s", request.getSecretId()));
    }

    /**
     * Adds metadata to the given secret.
     *
     * @param request the secret metadata update request
     * @throws DeltaServiceException upon service exception
     */
    public void updateSecretMetadata(UpdateSecretMetadataRequest request)
            throws DeltaServiceException {
        executeCallAndReturnResponse(deltaApi.updateSecretMetadata(
                request.getIdentityId(),
                request.getVersion(),
                request.getSecretId(),
                request.getMetadata()),
                format("Error updating metadata for secret %s", request.getSecretId()));
    }

    /**
     * Shares the base secret with the specified target RSA key owner. The
     * contents must be encrypted with the public encryption key of the
     * RSA key owner, and the encrypted key and initialisation vector must
     * be provided. This call will result in a new derived secret being created
     * and returned as a response.
     *
     * @param request the share secret request
     * @return the secret response of the new derived secret
     * @throws DeltaServiceException upon service exception
     */
    public ShareSecretResponse shareSecret(ShareSecretRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.shareSecret(request.getIdentityId(), request),
                format("Error sharing secret %s", request.getBaseSecret()));
    }

    /**
     * Deletes the secret with the given secret id.
     *
     * @param request the secret deletion request
     * @throws DeltaServiceException upon service exception
     */
    public void deleteSecret(SecretRequest request) throws DeltaServiceException {
        executeCallAndReturnResponse(
                deltaApi.deleteSecret(request.getIdentityId(), request.getSecretId()),
                format("Error deleting secret %s", request.getSecretId()));
    }

    /**
     * Gets a list of events associated filtered by secret id or RSA key owner
     * or both secret id and RSA key owner
     *
     * @param request the audit events retrieval request
     * @return the event responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetEventResponse> getEvents(GetEventsRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getEvents(
                        request.getIdentityId(),
                        request.getSecretId().orElse(null),
                        request.getRsaKeyOwner().orElse(null)),
                format("Error getting events for secret %s, rsaKeyOwner %s",
                        request.getSecretId(), request.getRsaKeyOwner()));
    }

    /**
     * Gets a list of secrets derived from the base secret, bound by the
     * pagination parameters.
     *
     * @param request the derived secrets retrieval request
     * @return the derived secret responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetSecretsResponse> getDerivedSecrets(GetDerivedSecretsRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getDerivedSecrets(
                        request.getIdentityId(),
                        request.getBaseSecretId(),
                        request.getIdentityId(),
                        request.getPage().orElse(null),
                        request.getPageSize().orElse(null)),
                format("Error getting derived secrets of secret %s", request.getBaseSecretId()));
    }

    /**
     * Gets a list of identities matching the given metadata key and value
     * pairs, bound by the pagination parameters.
     *
     * @param request the identity lookup by metadata request
     * @return the identity responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetIdentityResponse> getIdentitiesByMetadata(GetIdentitiesByMetadataRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getIdentitiesByMetadata(
                        request.getIdentityId(),
                        formatMetadata(request.getMetadata()),
                        request.getPage().orElse(null),
                        request.getPageSize().orElse(null)),
                "Error getting identities by metadata");
    }

    /**
     * Update the metadata for the given identity.
     *
     * @param request the update identity metadata request
     * @throws DeltaServiceException upon service exception
     */
    public void updateIdentityMetadata(UpdateIdentityMetadataRequest request)
            throws DeltaServiceException {
        executeCallAndReturnResponse(deltaApi
                        .updateIdentityMetadata(request.getIdentityId(),
                                request.getVersion(),
                                request.getIdentityIdToUpdate(),
                                request),
                String.format("Error updating metadata for identity %s", request.getIdentityId()));
    }

    /**
     * Gets a list of base secrets matching the given creator and metadata key
     * and value pairs, bound by the pagination parameters.
     *
     * @param request the secret retrieval request
     * @return the secret responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetSecretsResponse> getBaseSecretsByMetadata(GetBaseSecretsByMetadataRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getBaseSecrets(
                        request.getIdentityId(),
                        request.getCreatedBy(),
                        request.getMetadata()
                                .map(this::formatMetadata)
                                .orElse(Collections.emptyMap()),
                        request.getPage().orElse(null),
                        request.getPageSize().orElse(null)),
                "Error getting secrets by metadata");
    }

    /**
     * Gets a list of derived secrets matching the given RSA key owner and
     * metadata key and value pairs, bound by the pagination parameters.
     *
     * @param request the secret retrieval request
     * @return the secret responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetSecretsResponse> getDerivedSecretsByMetadata(GetDerivedSecretsByMetadataRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getDerivedSecrets(
                        request.getIdentityId(),
                        null,
                        request.getRsaKeyOwnerId(),
                        request.getMetadata()
                                .map(this::formatMetadata)
                                .orElse(Collections.emptyMap()),
                        request.getPage().orElse(null),
                        request.getPageSize().orElse(null)),
                "Error getting secrets by metadata");
    }

    /**
     * Gets a list of secrets shared by the given identity bound by the
     * pagination parameters.
     *
     * @param request the secret retrieval request
     * @return the secret responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetSecretsResponse> getSharedSecrets(GetSecretsRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getDerivedSecrets(
                        request.getIdentityId(),
                        request.getIdentityId(),
                        null,
                        request.getMetadata()
                                .map(this::formatMetadata)
                                .orElse(Collections.emptyMap()),
                        request.getPage().orElse(null),
                        request.getPageSize().orElse(null)),
                format("Error getting shared secrets for identity %s", request.getIdentityId()));
    }

    /**
     * Gets a list of secrets shared with the given identity bound by the
     * pagination parameters.
     *
     * @param request the secret retrieval request
     * @return the secret responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetSecretsResponse> getSecretsSharedWithMe(GetSecretsRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getDerivedSecrets(
                        request.getIdentityId(),
                        null,
                        request.getIdentityId(),
                        request.getMetadata()
                                .map(this::formatMetadata)
                                .orElse(Collections.emptyMap()),
                        request.getPage().orElse(null),
                        request.getPageSize().orElse(null)),
                format("Error getting secrets shared with identity %s", request.getIdentityId()));
    }

    /**
     * Gets a list of secrets owned by the given identity bound by the
     * pagination parameters.
     *
     * @param request the secret retrieval request
     * @return the secret responses matching the request
     * @throws DeltaServiceException upon service exception
     */
    public List<GetSecretsResponse> getOwnedSecrets(GetSecretsRequest request)
            throws DeltaServiceException {
        return executeCallAndReturnResponse(
                deltaApi.getBaseSecrets(request.getIdentityId(),
                        request.getIdentityId(),
                        request.getMetadata()
                                .map(this::formatMetadata)
                                .orElse(Collections.emptyMap()),
                        request.getPage().orElse(null),
                        request.getPageSize().orElse(null)),
                format("Error getting secrets owned by identity %s", request.getIdentityId()));
    }

    private Map<String, String> formatMetadata(Map<String, String> metadata) {
        return metadata.entrySet()
                .stream()
                .collect(Collectors.toMap(
                        entry -> "metadata." + entry.getKey(),
                        Map.Entry::getValue));
    }
}
