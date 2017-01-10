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
import com.covata.delta.sdk.api.common.EncryptionDetails;
import com.covata.delta.sdk.api.request.CreateIdentityRequest;
import com.covata.delta.sdk.api.request.CreateSecretRequest;
import com.covata.delta.sdk.api.request.GetBaseSecretsByMetadataRequest;
import com.covata.delta.sdk.api.request.GetDerivedSecretsByMetadataRequest;
import com.covata.delta.sdk.api.request.GetDerivedSecretsRequest;
import com.covata.delta.sdk.api.request.GetEventsRequest;
import com.covata.delta.sdk.api.request.GetIdentitiesByMetadataRequest;
import com.covata.delta.sdk.api.request.GetSecretsRequest;
import com.covata.delta.sdk.api.request.SecretRequest;
import com.covata.delta.sdk.api.request.ShareSecretRequest;
import com.covata.delta.sdk.api.request.UpdateIdentityMetadataRequest;
import com.covata.delta.sdk.api.request.UpdateSecretMetadataRequest;
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
import com.covata.delta.sdk.test.util.FileUtil;
import com.covata.delta.sdk.test.util.SharedTestKeys;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import okhttp3.ConnectionSpec;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DeltaApiClientTest {

    private static final String IDENTITY_ID = "10b73150-5357-48bc-a5fe-5377df6fa326";

    private static final String SECRET_ID = "c6aa4948-6201-4feb-8934-aa3f4f832d1e";

    private static final int PAGE_ONE = 1;

    private static final int LOOKUP_PAGE_SIZE = 25;

    private static final String CVT_IDENTITY_ID = "Cvt-Identity-Id";

    private static final String ATTR_SIGNING_PUBLIC_KEY = "signingPublicKey";

    private static final String ATTR_CRYPTO_PUBLIC_KEY = "cryptoPublicKey";

    private static final String ATTR_METADATA = "metadata";

    private static final ImmutableMap<String, String> METADATA = ImmutableMap.of(
            "city", "Sydney",
            "country", "Australia");

    private MockWebServer mockWebServer;

    private DeltaApiClient apiClient;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Before
    public void setup() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        ObjectMapper objectMapper = new ObjectMapper().disable(
                MapperFeature.AUTO_DETECT_CREATORS,
                MapperFeature.AUTO_DETECT_FIELDS,
                MapperFeature.AUTO_DETECT_GETTERS,
                MapperFeature.AUTO_DETECT_IS_GETTERS)
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

        DeltaApi deltaApi = new Retrofit.Builder()
                .baseUrl(mockWebServer.url("").toString())
                .addConverterFactory(JacksonConverterFactory.create(objectMapper))
                .build()
                .create(DeltaApi.class);

        apiClient = new DeltaApiClient(deltaApi);
    }

    @Test
    public void shouldReturnValidResponseGivenValidClientRegisterRequest()
            throws Exception {
        MockResponse mockResponse = new MockResponse()
                .setBody(FileUtil.readFile("register.json"));
        mockWebServer.enqueue(mockResponse);

        final String testSigningKey = "testSigningKey";

        final String testEncryptionKey = "testEncryptionKey";

        CreateIdentityRequest request = new CreateIdentityRequest(
                testSigningKey, testEncryptionKey, null, null);

        String clientId = apiClient.createIdentity(request).getIdentityId();

        Map expectedRequestBody = ImmutableMap.of(
                ATTR_CRYPTO_PUBLIC_KEY, testEncryptionKey,
                ATTR_SIGNING_PUBLIC_KEY, testSigningKey);

        assertThat(getBodyAsMap(mockWebServer.takeRequest()), equalTo(expectedRequestBody));

        assertEquals(clientId, IDENTITY_ID);
    }

    @Test
    public void shouldThrowExceptionIfRegisterRequestUnsuccessful()
            throws Exception {
        MockResponse mockResponse = new MockResponse().setResponseCode(400);
        mockWebServer.enqueue(mockResponse);

        Map<String, String> metadata = ImmutableMap.of(
                "", "empty key",
                "@$!", "key containing special characters");

        final String testSigningKey = "testSigningKey";

        final String testEncryptionKey = "testEncryptionKey";

        CreateIdentityRequest request = new CreateIdentityRequest(
                testSigningKey, testEncryptionKey, null, metadata);

        thrown.expect(DeltaServiceException.class);
        thrown.expectMessage("Bad Request");

        apiClient.createIdentity(request);
        Map expectedRequestBody = ImmutableMap.of(
                ATTR_CRYPTO_PUBLIC_KEY, testEncryptionKey,
                ATTR_SIGNING_PUBLIC_KEY, testSigningKey,
                ATTR_METADATA, metadata);
        assertThat(getBodyAsMap(mockWebServer.takeRequest()), equalTo(expectedRequestBody));
    }

    @Test
    public void shouldThrowBadRequestDeltaServiceException()
            throws DeltaServiceException {
        MockResponse mockResponse = new MockResponse().setResponseCode(400);
        mockWebServer.enqueue(mockResponse);

        thrown.expect(DeltaServiceException.class);
        thrown.expectMessage("Bad Request");

        apiClient.deleteSecret(new SecretRequest(IDENTITY_ID, SECRET_ID));
    }

    @Test
    public void shouldThrowUnableToAuthenticateDeltaServiceException()
            throws DeltaServiceException {
        MockResponse mockResponse = new MockResponse().setResponseCode(401);
        mockWebServer.enqueue(mockResponse);

        thrown.expect(DeltaServiceException.class);
        thrown.expectMessage("Unauthorized");

        apiClient.deleteSecret(new SecretRequest(IDENTITY_ID, SECRET_ID));
    }

    @Test
    public void shouldThrowPreconditionFailedDeltaServiceException() throws Exception {
        thrown.expect(DeltaServiceException.class);
        thrown.expectMessage("Precondition Failed");
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setResponseCode(412));
        UpdateSecretMetadataRequest updateMetadataRequest = new UpdateSecretMetadataRequest(IDENTITY_ID, SECRET_ID, 0L, METADATA);

        // make a test call
        createDeltaApiClient().updateSecretMetadata(updateMetadataRequest);
    }

    @Test
    public void shouldThrowInternalServerErrorDeltaServiceException()
            throws DeltaServiceException {
        MockResponse mockResponse = new MockResponse().setResponseCode(500);
        mockWebServer.enqueue(mockResponse);

        thrown.expect(DeltaServiceException.class);
        thrown.expectMessage("Internal Server Error");

        apiClient.deleteSecret(new SecretRequest(IDENTITY_ID, SECRET_ID));
    }

    @Test
    public void shouldReturnValidResponseGivenValidSecretMetadata()
            throws DeltaServiceException, InterruptedException {
        MockResponse mockResponse = new MockResponse().setBody(FileUtil.readFile("getBaseSecretsByMetadata.json"));
        mockWebServer.enqueue(mockResponse);

        String key = "name";
        String value = "DSS";

        List<GetSecretsResponse> response = apiClient.getBaseSecretsByMetadata(GetBaseSecretsByMetadataRequest
                .builder(IDENTITY_ID)
                .withCreatedBy(IDENTITY_ID)
                .withMetadata(ImmutableMap.of(key, value))
                .withPage(PAGE_ONE)
                .withPageSize(LOOKUP_PAGE_SIZE)
                .build());

        RecordedRequest request = mockWebServer.takeRequest();

        assertThat(request.getMethod(), is("GET"));
        assertThat(request.getHeader(CVT_IDENTITY_ID), is(IDENTITY_ID));

        Map<String, String> expected = ImmutableMap.<String, String>builder()
                .put("baseSecret", "false")
                .put("createdBy", IDENTITY_ID)
                .put("metadata." + key, value)
                .put("page", Integer.toString(PAGE_ONE))
                .put("pageSize", Integer.toString(LOOKUP_PAGE_SIZE)).build();

        assertThat(getQueryStringParameters(request.getPath()), equalTo(expected));
        assertEquals(2, response.size());

        response.forEach(getSecretsResponse -> {
            assertEquals(IDENTITY_ID, getSecretsResponse.getCreatedBy());
            assertNull(getSecretsResponse.getBaseSecret());
            assertThat(getSecretsResponse.getMetadata().get(key), is(value));
        });
    }

    @Test
    public void shouldReturnValidResponseGivenValidDerivedSecretMetadata()
            throws DeltaServiceException, InterruptedException {
        MockResponse mockResponse = new MockResponse().setBody(FileUtil.readFile("getDerivedSecretsByMetadata.json"));
        mockWebServer.enqueue(mockResponse);
        String key = "name";
        String value = "DSS";
        String rsaKeyOwnerId = "4ae53248-e6cb-49f8-a216-72a584f9515f";

        List<GetSecretsResponse> response = apiClient.getDerivedSecretsByMetadata(GetDerivedSecretsByMetadataRequest
                .builder(IDENTITY_ID)
                .withRsaKeyOwnerId(rsaKeyOwnerId)
                .withMetadata(ImmutableMap.of(key, value))
                .withPage(PAGE_ONE)
                .withPageSize(LOOKUP_PAGE_SIZE).build());

        RecordedRequest request = mockWebServer.takeRequest();

        assertThat(request.getMethod(), is("GET"));
        assertThat(request.getHeader(CVT_IDENTITY_ID), is(IDENTITY_ID));

        Map<String, String> expectedQueryString = ImmutableMap.<String, String>builder()
                .put("baseSecret", "true")
                .put("rsaKeyOwner", rsaKeyOwnerId)
                .put("metadata." + key, value)
                .put("page", Integer.toString(PAGE_ONE))
                .put("pageSize", Integer.toString(LOOKUP_PAGE_SIZE)).build();

        assertThat(getQueryStringParameters(request.getPath()), equalTo(expectedQueryString));

        assertEquals(2, response.size());
        response.forEach(getSecretsResponse -> {
            assertEquals(rsaKeyOwnerId, getSecretsResponse.getRsaKeyOwner());
            assertNotNull(rsaKeyOwnerId, getSecretsResponse.getBaseSecret());
            assertThat(getSecretsResponse.getMetadata().get(key), is(value));
        });
    }

    @Test
    public void shouldReturnValidResponseForListSharedSecrets()
            throws DeltaServiceException, InterruptedException {
        MockResponse mockResponse = new MockResponse().setBody(
                FileUtil.readFile("getSharedSecrets.json"));
        mockWebServer.enqueue(mockResponse);

        List<GetSecretsResponse> response =
                apiClient.getSharedSecrets(GetSecretsRequest
                        .builder(IDENTITY_ID)
                        .withPage(PAGE_ONE)
                        .withPageSize(LOOKUP_PAGE_SIZE)
                        .build());

        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod(), is("GET"));
        assertThat(request.getHeader(CVT_IDENTITY_ID), is(IDENTITY_ID));

        Map<String, String> expectedQueryString = ImmutableMap.<String, String>builder()
                .put("baseSecret", "true")
                .put("createdBy", IDENTITY_ID)
                .put("page", Integer.toString(PAGE_ONE))
                .put("pageSize", Integer.toString(LOOKUP_PAGE_SIZE)).build();

        assertThat(getQueryStringParameters(request.getPath()), equalTo(expectedQueryString));
        assertEquals(1, response.size());
        assertEquals(IDENTITY_ID, response.get(0).getCreatedBy());
    }

    @Test
    public void shouldReturnValidResponseForListSecretsSharedWithMe()
            throws DeltaServiceException, InterruptedException {
        MockResponse mockResponse = new MockResponse().setBody(
                FileUtil.readFile("getSecretsSharedWithMe.json"));
        mockWebServer.enqueue(mockResponse);

        List<GetSecretsResponse> response =
                apiClient.getSecretsSharedWithMe(GetSecretsRequest
                        .builder(IDENTITY_ID)
                        .withPage(PAGE_ONE)
                        .withPageSize(LOOKUP_PAGE_SIZE)
                        .build());

        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod(), is("GET"));
        assertThat(request.getHeader(CVT_IDENTITY_ID), is(IDENTITY_ID));

        Map<String, String> expectedQueryString = ImmutableMap.<String, String>builder()
                .put("baseSecret", "true")
                .put("rsaKeyOwner", IDENTITY_ID)
                .put("page", Integer.toString(PAGE_ONE))
                .put("pageSize", Integer.toString(LOOKUP_PAGE_SIZE)).build();

        assertThat(getQueryStringParameters(request.getPath()), equalTo(expectedQueryString));

        assertEquals(1, response.size());
        assertEquals(IDENTITY_ID, response.get(0).getRsaKeyOwner());
    }

    @Test
    public void shouldReturnValidResponseForListOwnedSecrets()
            throws DeltaServiceException, InterruptedException {
        MockResponse mockResponse = new MockResponse().setBody(
                FileUtil.readFile("getOwnedSecrets.json"));
        mockWebServer.enqueue(mockResponse);

        List<GetSecretsResponse> response =
                apiClient.getOwnedSecrets(GetSecretsRequest
                        .builder(IDENTITY_ID)
                        .withPage(PAGE_ONE)
                        .withPageSize(LOOKUP_PAGE_SIZE)
                        .build());

        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod(), is("GET"));
        assertThat(request.getHeader(CVT_IDENTITY_ID), is(IDENTITY_ID));

        Map<String, String> expectedQueryString = ImmutableMap.<String, String>builder()
                .put("baseSecret", "false")
                .put("createdBy", IDENTITY_ID)
                .put("page", Integer.toString(PAGE_ONE))
                .put("pageSize", Integer.toString(LOOKUP_PAGE_SIZE)).build();

        assertThat(getQueryStringParameters(request.getPath()), equalTo(expectedQueryString));

        assertEquals(3, response.size());
        response.forEach(getSecretResponse ->
                assertEquals(IDENTITY_ID, getSecretResponse.getRsaKeyOwner()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireApiUrl() throws Exception {
        new DeltaApiClient(mock(DeltaClientConfig.class), mock(DeltaKeyStore.class));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldReturnValidResponseGivenValidSecretCreationRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("createSecret.json")));

        // create request
        String content = "base64String";
        String secretKey = BaseEncoding.base64().encode(SharedTestKeys.SECRET_KEY_A.getEncoded());
        CreateSecretRequest createSecretRequest = new CreateSecretRequest(IDENTITY_ID, content, new EncryptionDetails(secretKey, "1"));

        // make a test call
        CreateSecretResponse response = createDeltaApiClient().createSecret(createSecretRequest);

        // assert response
        assertEquals(SECRET_ID, response.getSecretId());

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        Map<String, Object> requestBody = getBodyAsMap(request);
        assertEquals(content, requestBody.get("content"));
        Map<String, String> encryptionDetails = (Map<String, String>) requestBody.get("encryptionDetails");
        assertEquals("1", encryptionDetails.get("initialisationVector"));
        assertEquals(secretKey, encryptionDetails.get("symmetricKey"));
    }

    @Test
    public void shouldReturnValidResponseGivenValidGetSecretRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("getSecret.json")));
        SecretRequest secretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);

        // make a test call
        GetSecretResponse response = createDeltaApiClient().getSecret(secretRequest);

        // assert the response
        assertEquals(SECRET_ID, response.getId());
        assertEquals("2016-08-23T17:02:47Z", response.getCreated());
        assertEquals("b15e50ea-ce07-4a3d-a4fc-0cd6b4d9ab13", response.getCreatedBy());
        assertEquals(IDENTITY_ID, response.getRsaKeyOwner());

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertTrue(request.getPath().endsWith("/" + SECRET_ID));
    }

    @Test
    public void shouldReturnValidResponseGivenValidGetSecretContentRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("getSecretContent.json")));
        SecretRequest secretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);

        // make a test call
        String response = createDeltaApiClient().getSecretContent(secretRequest);

        // assert the response
        assertEquals("base64String", response);

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertTrue(request.getPath().endsWith("/" + SECRET_ID + "/content"));
    }

    @Test
    public void shouldReturnValidResponseGivenValidGetSecretMetadataRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse()
                .setBody(FileUtil.readFile("getSecretMetadata.json"))
                .addHeader(HttpHeaders.ETAG, "2"));
        SecretRequest secretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);

        // make a test call
        GetSecretMetadataResponse response = createDeltaApiClient().getSecretMetadata(secretRequest);

        // assert the response
        assertEquals(METADATA, response.getMetadata());

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertTrue(request.getPath().endsWith("/" + SECRET_ID + "/metadata"));
    }

    @Test
    public void shouldReturnValidResponseGivenValidUpdateSecretMetadataRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setResponseCode(201));
        UpdateSecretMetadataRequest updateMetadataRequest = new UpdateSecretMetadataRequest(IDENTITY_ID, SECRET_ID, 1L, METADATA);

        // make a test call
        createDeltaApiClient().updateSecretMetadata(updateMetadataRequest);

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertEquals("PUT", request.getMethod());
        assertTrue(request.getPath().endsWith("/" + SECRET_ID + "/metadata"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldReturnValidResponseGivenValidShareSecretRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("shareSecret.json")));

        // create request
        String content = "base64String";
        String secretKey = BaseEncoding.base64().encode(SharedTestKeys.SECRET_KEY_A.getEncoded());
        ShareSecretRequest shareSecretRequest = new ShareSecretRequest(
                IDENTITY_ID,
                "baseSecret",
                "rsaKeyOwner",
                content,
                new EncryptionDetails(secretKey, "1"));

        // make a test call
        ShareSecretResponse response = createDeltaApiClient().shareSecret(shareSecretRequest);

        // assert the response
        assertEquals(SECRET_ID, response.getSecretId());
        assertEquals("abc", response.getHref());

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertEquals("POST", request.getMethod());
        Map<String, Object> requestBody = getBodyAsMap(request);
        assertEquals(content, requestBody.get("content"));
        assertEquals("baseSecret", requestBody.get("baseSecret"));
        assertEquals("rsaKeyOwner", requestBody.get("rsaKeyOwner"));
        Map<String, String> encryptionDetails = (Map<String, String>) requestBody.get("encryptionDetails");
        assertEquals("1", encryptionDetails.get("initialisationVector"));
        assertEquals(secretKey, encryptionDetails.get("symmetricKey"));
    }

    @Test
    public void shouldReturnValidResponseGivenValidDeleteSecretRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setResponseCode(204));
        SecretRequest secretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);

        // make a test call
        createDeltaApiClient().deleteSecret(secretRequest);

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertEquals("DELETE", request.getMethod());
        assertTrue(request.getPath().endsWith("/" + SECRET_ID));
    }

    @Test
    public void shouldReturnValidResponseGivenValidGetEventsBySecretRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("getEvents.json")));
        GetEventsRequest getEventsRequest = new GetEventsRequest(IDENTITY_ID, SECRET_ID, "rsaKeyOwner");

        // make a test call
        List<GetEventResponse> response = createDeltaApiClient().getEvents(getEventsRequest);

        // assert the response
        assertEquals(1, response.size());
        GetEventResponse event = response.get(0);
        assertEquals("067e6162-3b6f-4ae2-a171-2470b63dff00", event.getId());
        assertEquals("1.1.1.1", event.getSourceIp());
        assertEquals("2016-11-04T17:02:47Z", event.getTimestamp());
        assertEquals("eventType", event.getType());
        assertEquals("example.server", event.getHost());
        assertEquals("baseSecretId", event.getEventDetails().getBaseSecretId());
        assertEquals("rsaKeyOwnerId", event.getEventDetails().getRsaKeyOwnerId());
        assertEquals("secretOwnerId", event.getEventDetails().getSecretOwnerId());
        assertEquals("requesterId", event.getEventDetails().getRequesterId());

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertEquals("GET", request.getMethod());
        assertTrue(request.getPath().endsWith("events/?purpose=AUDIT&secretId=" + SECRET_ID + "&rsaKeyOwner=rsaKeyOwner"));
    }

    @Test
    public void shouldReturnValidResponseGivenValidGetDerivedSecretsRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("getDerivedSecrets.json")));
        GetDerivedSecretsRequest getDerivedSecretsRequest = new GetDerivedSecretsRequest(IDENTITY_ID, SECRET_ID, 0, 10);

        // make a test call
        List<GetSecretsResponse> response = createDeltaApiClient().getDerivedSecrets(getDerivedSecretsRequest);

        // assert the response
        assertEquals(1, response.size());
        GetSecretsResponse secret = response.get(0);
        assertEquals(SECRET_ID, secret.getId());
        assertEquals("https://example.server/secrets/067e6162-3b6f-4ae2-a171-2470b63dff00", secret.getHref());
        assertEquals("b15e50ea-ce07-4a3d-a4fc-0cd6b4d9ab13", secret.getCreatedBy());
        assertEquals("2016-08-23T17:02:47Z", secret.getCreated());
        assertEquals("eb4f44d0-1b47-4981-9661-1c1101d7a049", secret.getBaseSecret());
        assertEquals(METADATA, secret.getMetadata());

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertEquals("GET", request.getMethod());
        assertTrue(request.getPath()
                .endsWith("/secrets?baseSecret=" + SECRET_ID + "&createdBy=" + IDENTITY_ID + "&page=0&pageSize=10"));
    }

    @Test
    public void shouldReturnValidResponseGivenValidGetIdentitiesByMetadataRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("getIdentitiesByMetadata.json")));
        GetIdentitiesByMetadataRequest getIdentitiesByMetadataRequest = new GetIdentitiesByMetadataRequest(IDENTITY_ID, METADATA, 0, 10);

        // make a test call
        List<GetIdentityResponse> response = createDeltaApiClient().getIdentitiesByMetadata(getIdentitiesByMetadataRequest);

        // assert the response
        assertEquals(1, response.size());
        GetIdentityResponse identity = response.get(0);
        assertEquals(IDENTITY_ID, identity.getId());
        assertEquals("ck", identity.getEncryptionPublicKey());
        assertEquals("abc", identity.getExternalId());
        assertThat(identity.getVersion(), is(10L));
        assertEquals(METADATA, identity.getMetadata());

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertEquals("GET", request.getMethod());
        ImmutableMap<String, String> expectedQueryParameters = ImmutableMap.of(
                "metadata.city", "Sydney",
                "metadata.country", "Australia",
                "page", "0",
                "pageSize", "10");
        assertEquals(expectedQueryParameters, getQueryStringParameters(request.getPath()));
    }

    @Test
    public void shouldReturnValidResponseGivenValidUpdateIdentityMetadataRequest() throws Exception {
        // set up mock server
        mockWebServer.enqueue(new MockResponse().setBody(FileUtil.readFile("getIdentitiesByMetadata.json")));
        UpdateIdentityMetadataRequest updateIdentityMetadataRequest = new UpdateIdentityMetadataRequest(
                IDENTITY_ID,
                "identity2",
                10L,
                METADATA);

        // make a test call
        createDeltaApiClient().updateIdentityMetadata(updateIdentityMetadataRequest);

        // assert the request we made during the test call
        RecordedRequest request = mockWebServer.takeRequest(1, TimeUnit.SECONDS);
        assertEquals(IDENTITY_ID, getAuthIdentity(request.getHeader(AUTHORIZATION)));
        assertEquals("PUT", request.getMethod());
        assertTrue(request.getPath().endsWith("/identity2"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getBodyAsMap(RecordedRequest request) throws IOException, JsonParseException, JsonMappingException {
        return new ObjectMapper().readValue(request.getBody().readUtf8(), Map.class);
    }

    private DeltaApiClient createDeltaApiClient() throws DeltaClientException {
        DeltaClientConfig configMock = mock(DeltaClientConfig.class);
        when(configMock.getApiUrl()).thenReturn(mockWebServer.url("").toString() + "/");
        when(configMock.getConnectionTimeoutSeconds()).thenReturn(5);

        DeltaKeyStore keyStoreMock = mock(DeltaKeyStore.class);
        when(keyStoreMock.getPrivateEncryptionKey(IDENTITY_ID)).thenReturn(SharedTestKeys.CRYPTO_KEY_PAIR.getPrivate());
        when(keyStoreMock.getPrivateSigningKey(IDENTITY_ID)).thenReturn(SharedTestKeys.SIGNING_KEY_PAIR.getPrivate());

        return new DeltaApiClient(configMock, keyStoreMock, ConnectionSpec.CLEARTEXT);
    }

    private Map<String, String> getQueryStringParameters(String url) {
        ImmutableMap.Builder<String, String> params = ImmutableMap.builder();
        int queryStartPos = url.indexOf('?');
        if (queryStartPos == -1) {
            return params.build();
        }
        String query = url.substring(queryStartPos + 1);
        for (String param : query.split("&")) {
            String[] kv = param.split("=");
            params.put(kv[0], kv[1]);
        }
        return params.build();
    }

    private String getAuthIdentity(String auth) {
        if (!Strings.isNullOrEmpty(auth)) {
            Pattern p = Pattern.compile(".*identity=(.*), signedheaders=.*");
            Matcher m = p.matcher(auth.toLowerCase());
            return m.matches() ? m.group(1) : "";
        } else {
            return "";
        }
    }

}
