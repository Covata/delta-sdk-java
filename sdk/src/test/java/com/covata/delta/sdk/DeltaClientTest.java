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

import static com.covata.delta.sdk.test.util.SharedTestKeys.CRYPTO_KEY_PAIR;
import static com.covata.delta.sdk.test.util.SharedTestKeys.CRYPTO_PUBLIC_KEY_BASE64;
import static com.covata.delta.sdk.test.util.SharedTestKeys.SECRET_KEY_A;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.covata.delta.sdk.api.DeltaApiClient;
import com.covata.delta.sdk.api.common.EncryptionDetails;
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
import com.covata.delta.sdk.api.response.GetEventResponse.EventDetails;
import com.covata.delta.sdk.api.response.GetIdentityResponse;
import com.covata.delta.sdk.api.response.GetSecretMetadataResponse;
import com.covata.delta.sdk.api.response.GetSecretResponse;
import com.covata.delta.sdk.api.response.GetSecretsResponse;
import com.covata.delta.sdk.api.response.ShareSecretResponse;
import com.covata.delta.sdk.crypto.CryptoService;
import com.covata.delta.sdk.crypto.DeltaKeyStore;
import com.covata.delta.sdk.model.DeltaEvent;
import com.covata.delta.sdk.model.DeltaIdentity;
import com.covata.delta.sdk.model.DeltaSecret;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.BaseEncoding;

public class DeltaClientTest {

    private DeltaClient deltaClient;

    private DeltaClientConfig config;

    private DeltaKeyStore mockKeyStore;

    private CryptoService mockCryptoService;

    private DeltaApiClient mockApiClient;

    private static final String REQUEST_DATE = "20150830T123600Z";

    private static final String IDENTITY_ID = UUID.randomUUID().toString();

    private static final String OTHER_IDENTITY_ID = UUID.randomUUID().toString();

    private static final String EXTERNAL_ID = "external";

    private static final Map<String, String> METADATA = ImmutableMap.of("name", "DSS");

    private static final String IV_BASE64 = "vjs0zI9Zy1O10WwjqHEcAg==";

    private static final Supplier<byte[]> IV_SUPPLIER = () -> BaseEncoding.base64().decode(IV_BASE64);

    private static final String CONTENT_BASE64 = "fjjcjNAEgVFttscp3hYxk7fjlX+P07Eucflrn/TUTx4A7z9U";

    private static final String ENCRYPTED_KEY_BASE64 = "OxagNsAXKZ8tR5WoZETC68wVJueRH2OL17j606dMSpmYnL5kkreSGOpzVV602H8XHiRyZhl1OFfGTCWiydMw13m709H8RFYK3HZoPsPioeik/xmdfhoAJha43dEMvDBSxDNr05fNjZ0JfS0qYMjnZos+8s9frsFrG++QS5SjowqmwsO0LkVqrXarKUBCjKZZXYtiYtBiQGLLrgBBjsJb3mhd1XkgpLQdvGE232hgyqyIIbTbEqQGuwZyIzNqb8GSAaLrOwOTAA46x99WOefzrwu7Nyycny52lnbfQp2EhwshZCUaChNFyHs86TcYkeSDd3nyvHelbBYNH3KK4Qpw9A==";

    private static final String SECRET_ID = UUID.randomUUID().toString();

    private static final String SECRET_HREF = "https://test.com/secrets/" + SECRET_ID;

    private static final String SHARED_SECRET_ID = UUID.randomUUID().toString();

    private static final String SHARED_SECRET_HREF = "https://test.com/secrets/" + SHARED_SECRET_ID;

    private static final String FILE_NAME = "test.txt";

    private static final String PLAIN_TEXT = "Kontrast - Sean Tyas";

    private static final String MOCK_API_URL = "https://test.com/v1/";

    private static enum SecretType {
        BASE, DERIVED
    }

    @After
    public void tearDown() {
        File file = new File(FILE_NAME);
        if (file.exists()) {
            assertTrue(file.delete());
        }
    }

    @Before
    public void init() {
        mockApiClient = mock(DeltaApiClient.class);
        mockKeyStore = mock(DeltaKeyStore.class);
        mockCryptoService = mock(CryptoService.class);

        config = DeltaClientConfig.builder()
                .withApiUrl(MOCK_API_URL)
                .withApiClient(mockApiClient)
                .withKeyStore(mockKeyStore)
                .withCryptoService(mockCryptoService)
                .build();

        String mockKeyString = "keyString";

        when(mockCryptoService.generatePublicPrivateKey()).thenReturn(CRYPTO_KEY_PAIR);
        when(mockCryptoService.generateInitialisationVector()).thenReturn(IV_SUPPLIER.get());
        when(mockCryptoService.encrypt(any(byte[].class), eq(SECRET_KEY_A), eq(IV_SUPPLIER.get()))).thenReturn(CONTENT_BASE64);
        when(mockCryptoService.encrypt(anyString(), eq(SECRET_KEY_A), eq(IV_SUPPLIER.get()))).thenReturn(CONTENT_BASE64);
        when(mockCryptoService
                .decrypt(any(byte[].class), eq(SECRET_KEY_A), eq(IV_SUPPLIER.get())))
                .thenReturn(PLAIN_TEXT);
        when(mockCryptoService
                .decrypt(eq(CONTENT_BASE64), eq(ENCRYPTED_KEY_BASE64), eq(IV_SUPPLIER.get()), eq(IDENTITY_ID)))
                .thenReturn(PLAIN_TEXT);
        when(mockCryptoService.generateSecretKey()).thenReturn(SECRET_KEY_A);
        when(mockCryptoService.encryptKeyWithPublicKey(eq(SECRET_KEY_A), eq(CRYPTO_KEY_PAIR.getPublic()))).thenReturn(ENCRYPTED_KEY_BASE64);
        when(mockCryptoService.decryptWithPrivateKey(eq(ENCRYPTED_KEY_BASE64), eq(CRYPTO_KEY_PAIR.getPrivate()))).thenReturn(mockKeyString);
        when(mockCryptoService.getSymmetricKey(mockKeyString)).thenReturn(SECRET_KEY_A);
        when(mockCryptoService.getPublicKey(eq(CRYPTO_PUBLIC_KEY_BASE64))).thenReturn(CRYPTO_KEY_PAIR.getPublic());

        when(mockKeyStore.getPublicEncryptionKey(eq(IDENTITY_ID))).thenReturn(CRYPTO_KEY_PAIR.getPublic());
        when(mockKeyStore.getPrivateEncryptionKey(eq(IDENTITY_ID))).thenReturn(CRYPTO_KEY_PAIR.getPrivate());

        deltaClient = new DeltaClient(config);
    }

    @Test
    public void shouldCreateIdentityWithEmptyMetadataAndExternalId() {
        CreateIdentityResponse mockResponse = new CreateIdentityResponse(IDENTITY_ID);
        CreateIdentityRequest expectedRequest = CreateIdentityRequest
                .builder(CRYPTO_PUBLIC_KEY_BASE64, CRYPTO_PUBLIC_KEY_BASE64)
                .withMetadata(Collections.emptyMap())
                .build();

        DeltaIdentity expectedCreatedIdentity = DeltaIdentity.builder(deltaClient)
                .withId(mockResponse.getIdentityId())
                .withEncryptionPublicKey(CRYPTO_PUBLIC_KEY_BASE64)
                .withSigningPublicKey(CRYPTO_PUBLIC_KEY_BASE64)
                .build();

        when(mockApiClient.createIdentity(eq(expectedRequest))).thenReturn(mockResponse);

        assertDeltaIdentityEquals(expectedCreatedIdentity, deltaClient.createIdentity());

        verify(mockCryptoService, times(2)).generatePublicPrivateKey();
        verify(mockKeyStore, times(1)).storeKeys(eq(IDENTITY_ID), eq(CRYPTO_KEY_PAIR), eq(CRYPTO_KEY_PAIR));
        verify(mockApiClient, times(1)).createIdentity(eq(expectedRequest));
    }

    @Test
    public void shouldCreateIdentityWithMetadataAndExternalId() {
        CreateIdentityResponse mockResponse = new CreateIdentityResponse(IDENTITY_ID);
        CreateIdentityRequest expectedRequest = CreateIdentityRequest
                .builder(CRYPTO_PUBLIC_KEY_BASE64, CRYPTO_PUBLIC_KEY_BASE64)
                .withExternalId(EXTERNAL_ID)
                .withMetadata(METADATA)
                .build();

        DeltaIdentity expectedCreatedIdentity = DeltaIdentity.builder(deltaClient)
                .withId(mockResponse.getIdentityId())
                .withEncryptionPublicKey(CRYPTO_PUBLIC_KEY_BASE64)
                .withSigningPublicKey(CRYPTO_PUBLIC_KEY_BASE64)
                .withExternalId(EXTERNAL_ID)
                .withMetadata(METADATA)
                .build();

        when(mockApiClient.createIdentity(eq(expectedRequest))).thenReturn(mockResponse);

        assertDeltaIdentityEquals(deltaClient.createIdentity(EXTERNAL_ID, METADATA), expectedCreatedIdentity);

        verify(mockCryptoService, times(2)).generatePublicPrivateKey();
        verify(mockKeyStore, times(1)).storeKeys(eq(IDENTITY_ID), eq(CRYPTO_KEY_PAIR), eq(CRYPTO_KEY_PAIR));
        verify(mockApiClient, times(1)).createIdentity(eq(expectedRequest));
    }

    @Test
    public void shouldGetRequestingIdentity() {
        GetIdentityResponse mockResponse = new GetIdentityResponse(
                IDENTITY_ID, CRYPTO_PUBLIC_KEY_BASE64,
                METADATA, EXTERNAL_ID, 1L);

        DeltaIdentity expectedIdentity = DeltaIdentity.builder(deltaClient)
                .withId(IDENTITY_ID)
                .withEncryptionPublicKey(CRYPTO_PUBLIC_KEY_BASE64)
                .withMetadata(METADATA)
                .withExternalId(EXTERNAL_ID)
                .withVersion(1L)
                .build();

        GetIdentityRequest expectedRequest = GetIdentityRequest.builder(IDENTITY_ID)
                .withIdentityIdToRetrieve(IDENTITY_ID)
                .build();

        when(mockApiClient.getIdentity(eq(expectedRequest))).thenReturn(mockResponse);

        assertDeltaIdentityEquals(expectedIdentity, deltaClient.getIdentity(IDENTITY_ID));
        verify(mockApiClient, times(1)).getIdentity(eq(expectedRequest));
    }

    @Test
    public void shouldGetOtherIdentity() {
        GetIdentityResponse mockResponse = new GetIdentityResponse(
                OTHER_IDENTITY_ID, CRYPTO_PUBLIC_KEY_BASE64,
                METADATA, EXTERNAL_ID, 1L);

        DeltaIdentity expectedIdentity = DeltaIdentity.builder(deltaClient)
                .withId(OTHER_IDENTITY_ID)
                .withEncryptionPublicKey(CRYPTO_PUBLIC_KEY_BASE64)
                .withMetadata(METADATA)
                .withExternalId(EXTERNAL_ID)
                .withVersion(1L)
                .build();

        GetIdentityRequest expectedRequest = GetIdentityRequest.builder(IDENTITY_ID)
                .withIdentityIdToRetrieve(OTHER_IDENTITY_ID)
                .build();

        when(mockApiClient.getIdentity(eq(expectedRequest))).thenReturn(mockResponse);

        assertDeltaIdentityEquals(expectedIdentity, deltaClient.getIdentity(IDENTITY_ID, OTHER_IDENTITY_ID));
        verify(mockApiClient, times(1)).getIdentity(eq(expectedRequest));
    }

    @Test
    public void shouldCreateSecretAndThenGetSecret() throws IOException {
        CreateSecretRequest expectedPostSecretRequest = CreateSecretRequest.builder(IDENTITY_ID)
                .withContent(CONTENT_BASE64)
                .withEncryptionDetails(ENCRYPTED_KEY_BASE64, IV_BASE64)
                .build();

        SecretRequest expectedGetSecretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);
        CreateSecretResponse mockPostSecretResponse = new CreateSecretResponse(SECRET_ID, SECRET_HREF);
        GetSecretResponse mockGetSecretResponse = new GetSecretResponse(
                SECRET_ID, IDENTITY_ID, IDENTITY_ID, REQUEST_DATE, REQUEST_DATE,
                new EncryptionDetails(ENCRYPTED_KEY_BASE64, IV_BASE64), true, SECRET_HREF);
        DeltaSecret expectedDeltaSecret = createDeltaSecretFromGetSecretResponse(mockGetSecretResponse);

        when(mockApiClient.createSecret(eq(expectedPostSecretRequest))).thenReturn(mockPostSecretResponse);
        when(mockApiClient.getSecret(eq(expectedGetSecretRequest))).thenReturn(mockGetSecretResponse);

        assertDeltaSecretEquals(expectedDeltaSecret, deltaClient.createSecret(IDENTITY_ID, createTestFile()));
        assertDeltaSecretEquals(expectedDeltaSecret, deltaClient.createSecret(IDENTITY_ID, PLAIN_TEXT));
        assertDeltaSecretEquals(
                expectedDeltaSecret,
                deltaClient.createSecret(IDENTITY_ID, PLAIN_TEXT.getBytes(config.getEncodingCharset())));

        verify(mockCryptoService, times(3)).generateSecretKey();
        verify(mockCryptoService, times(3)).generateInitialisationVector();
        verify(mockCryptoService, times(3)).encrypt(any(byte[].class), eq(SECRET_KEY_A), eq(IV_SUPPLIER.get()));
        verify(mockKeyStore, times(3)).getPublicEncryptionKey(eq(IDENTITY_ID));
        verify(mockCryptoService, times(3)).encryptKeyWithPublicKey(eq(SECRET_KEY_A), eq(CRYPTO_KEY_PAIR.getPublic()));
        verify(mockApiClient, times(3)).createSecret(eq(expectedPostSecretRequest));
        verify(mockApiClient, times(3)).getSecret(eq(expectedGetSecretRequest));
    }

    @Test
    public void shouldGetSecretEncryptedContent() {
        SecretRequest expectedGetSecretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);
        when(mockApiClient.getSecretContent(eq(expectedGetSecretRequest))).thenReturn(CONTENT_BASE64);

        String content = deltaClient.getSecretContentEncrypted(IDENTITY_ID, SECRET_ID);

        verify(mockApiClient, times(1)).getSecretContent(eq(expectedGetSecretRequest));
        assertThat(content, is(CONTENT_BASE64));
    }

    @Test
    public void shouldGetSecretDecryptedContent() {
        SecretRequest expectedGetSecretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);
        when(mockApiClient.getSecretContent(eq(expectedGetSecretRequest))).thenReturn(CONTENT_BASE64);

        String content = deltaClient.getSecretContent(IDENTITY_ID, SECRET_ID, ENCRYPTED_KEY_BASE64, IV_BASE64);

        verify(mockApiClient, times(1)).getSecretContent(eq(expectedGetSecretRequest));

        verify(mockKeyStore, times(1)).getPrivateEncryptionKey(eq(IDENTITY_ID));
        verify(mockCryptoService, times(1)).decryptWithPrivateKey(eq(ENCRYPTED_KEY_BASE64), eq(CRYPTO_KEY_PAIR.getPrivate()));
        verify(mockCryptoService, times(1)).decrypt(any(byte[].class), eq(SECRET_KEY_A), eq(IV_SUPPLIER.get()));
        assertThat(content, is(PLAIN_TEXT));
    }

    private File createTestFile() throws IOException {
        File file = new File(FILE_NAME);
        assertTrue(file.createNewFile());
        try (FileOutputStream os = new FileOutputStream(file, false)) {
            os.write(PLAIN_TEXT.getBytes(config.getEncodingCharset()));
        }
        return file;
    }

    @Test
    public void shouldGetSecretMetadata() {
        SecretRequest expectedRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);
        GetSecretMetadataResponse expectedResponse = new GetSecretMetadataResponse(METADATA, 1L);
        when(mockApiClient.getSecretMetadata(eq(expectedRequest))).thenReturn(expectedResponse);

        deltaClient.getSecretMetadata(IDENTITY_ID, SECRET_ID);

        verify(mockApiClient, times(1)).getSecretMetadata(eq(expectedRequest));
    }

    @Test
    public void shouldAddSecretMetadata() {
        Map<String, String> additionalMetadata = ImmutableMap.of("key", "value");

        Map<String, String> expectedUpdatedMetadata = ImmutableMap
                .<String, String>builder()
                .putAll(METADATA)
                .putAll(additionalMetadata)
                .build();

        SecretRequest expectedGetRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);
        UpdateSecretMetadataRequest expectedUpdateRequest = UpdateSecretMetadataRequest.builder(IDENTITY_ID)
                .withSecretId(SECRET_ID)
                .withVersion(1L)
                .withMetadata(expectedUpdatedMetadata)
                .build();

        GetSecretMetadataResponse expectedGetResponse = new GetSecretMetadataResponse(METADATA, 1L);
        when(mockApiClient.getSecretMetadata(eq(expectedGetRequest))).thenReturn(expectedGetResponse);
        doNothing().when(mockApiClient).updateSecretMetadata(expectedUpdateRequest);

        deltaClient.addSecretMetadata(IDENTITY_ID, SECRET_ID, 1L, additionalMetadata);

        verify(mockApiClient, times(1)).getSecretMetadata(eq(expectedGetRequest));
        verify(mockApiClient, times(1)).updateSecretMetadata(eq(expectedUpdateRequest));
    }

    @Test
    public void shouldRemoveSecretMetadata() {
        Collection<String> keysToRemove = Arrays.asList("name", "nonExistentKey");

        Map<String, String> expectedUpdatedMetadata = Collections.emptyMap();

        SecretRequest expectedGetRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);
        UpdateSecretMetadataRequest expectedUpdateRequest = UpdateSecretMetadataRequest.builder(IDENTITY_ID)
                .withSecretId(SECRET_ID)
                .withVersion(1L)
                .withMetadata(expectedUpdatedMetadata)
                .build();

        GetSecretMetadataResponse expectedGetResponse = new GetSecretMetadataResponse(METADATA, 1L);
        when(mockApiClient.getSecretMetadata(eq(expectedGetRequest))).thenReturn(expectedGetResponse);
        doNothing().when(mockApiClient).updateSecretMetadata(expectedUpdateRequest);

        deltaClient.removeSecretMetadata(IDENTITY_ID, SECRET_ID, 1L, keysToRemove);

        verify(mockApiClient, times(1)).getSecretMetadata(eq(expectedGetRequest));
        verify(mockApiClient, times(1)).updateSecretMetadata(eq(expectedUpdateRequest));
    }

    @Test
    public void shouldAddIdentityMetadata() {
        Map<String, String> additionalMetadata = ImmutableMap.of("key", "value");

        Map<String, String> expectedUpdatedMetadata = ImmutableMap
                .<String, String>builder()
                .putAll(METADATA)
                .putAll(additionalMetadata)
                .build();

        GetIdentityResponse expectedGetResponse = new GetIdentityResponse(
                IDENTITY_ID, CRYPTO_PUBLIC_KEY_BASE64,
                METADATA, EXTERNAL_ID, 1L);

        GetIdentityRequest expectedGetRequest = GetIdentityRequest.builder(IDENTITY_ID)
                .withIdentityIdToRetrieve(IDENTITY_ID)
                .build();

        when(mockApiClient.getIdentity(eq(expectedGetRequest))).thenReturn(expectedGetResponse);

        UpdateIdentityMetadataRequest expectedUpdateRequest = UpdateIdentityMetadataRequest.builder(IDENTITY_ID)
                .withIdentityIdToUpdate(IDENTITY_ID)
                .withVersion(1L)
                .withMetadata(expectedUpdatedMetadata)
                .build();

        deltaClient.addIdentityMetadata(IDENTITY_ID, 1L, additionalMetadata);

        verify(mockApiClient, times(1)).getIdentity(eq(expectedGetRequest));
        verify(mockApiClient, times(1)).updateIdentityMetadata(eq(expectedUpdateRequest));
    }

    @Test
    public void shouldRemoveIdentityMetadata() {
        Collection<String> keysToRemove = Arrays.asList("name", "nonExistentKey");

        Map<String, String> expectedUpdatedMetadata = Collections.emptyMap();

        GetIdentityResponse expectedGetResponse = new GetIdentityResponse(
                IDENTITY_ID, CRYPTO_PUBLIC_KEY_BASE64,
                METADATA, EXTERNAL_ID, 1L);

        GetIdentityRequest expectedGetRequest = GetIdentityRequest.builder(IDENTITY_ID)
                .withIdentityIdToRetrieve(IDENTITY_ID)
                .build();

        when(mockApiClient.getIdentity(eq(expectedGetRequest))).thenReturn(expectedGetResponse);

        UpdateIdentityMetadataRequest expectedUpdateRequest = UpdateIdentityMetadataRequest.builder(IDENTITY_ID)
                .withIdentityIdToUpdate(IDENTITY_ID)
                .withVersion(1L)
                .withMetadata(expectedUpdatedMetadata)
                .build();

        deltaClient.removeIdentityMetadata(IDENTITY_ID, 1L, keysToRemove);

        verify(mockApiClient, times(1)).getIdentity(eq(expectedGetRequest));
        verify(mockApiClient, times(1)).updateIdentityMetadata(eq(expectedUpdateRequest));
    }

    @Test
    public void shouldShareSecretWithOtherIdentity() {
        GetIdentityRequest expectedGetIdentityRequest = GetIdentityRequest.builder(IDENTITY_ID)
                .withIdentityIdToRetrieve(OTHER_IDENTITY_ID)
                .build();
        GetIdentityResponse mockGetIdentityResponse = new GetIdentityResponse(
                OTHER_IDENTITY_ID, CRYPTO_PUBLIC_KEY_BASE64, METADATA, EXTERNAL_ID, 1L);

        SecretRequest expectedGetSecretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);
        GetSecretResponse mockGetSecretResponse = new GetSecretResponse(
                SECRET_ID, IDENTITY_ID, IDENTITY_ID, REQUEST_DATE, REQUEST_DATE,
                new EncryptionDetails(ENCRYPTED_KEY_BASE64, IV_BASE64), false, SECRET_HREF);

        ShareSecretRequest expectedShareSecretRequest = ShareSecretRequest.builder(IDENTITY_ID)
                .withBaseSecret(SECRET_ID).withRsaKeyOwnerId(OTHER_IDENTITY_ID)
                .withContent(CONTENT_BASE64).withEncryptionDetails(ENCRYPTED_KEY_BASE64, IV_BASE64)
                .build();
        ShareSecretResponse mockShareSecretResponse = new ShareSecretResponse(SHARED_SECRET_ID, SHARED_SECRET_HREF);

        when(mockApiClient.getIdentity(eq(expectedGetIdentityRequest))).thenReturn(mockGetIdentityResponse);
        when(mockApiClient.getSecret(eq(expectedGetSecretRequest))).thenReturn(mockGetSecretResponse);
        when(mockApiClient.getSecretContent(eq(expectedGetSecretRequest))).thenReturn(CONTENT_BASE64);
        when(mockApiClient.shareSecret(eq(expectedShareSecretRequest))).thenReturn(mockShareSecretResponse);
        executeShareSecretTest(expectedGetIdentityRequest, expectedGetSecretRequest, expectedShareSecretRequest);
    }

    private void executeShareSecretTest(GetIdentityRequest expectedGetIdentityRequest,
                                        SecretRequest expectedGetSecretRequest,
                                        ShareSecretRequest expectedShareSecretRequest) {

        DeltaSecret expectedSecret = DeltaSecret.builder(deltaClient, mockCryptoService)
                .withId(SHARED_SECRET_ID)
                .withBaseSecret(SECRET_ID)
                .withRsaKeyOwnerId(OTHER_IDENTITY_ID)
                .withCreatedBy(IDENTITY_ID)
                .withSymmetricKey(ENCRYPTED_KEY_BASE64)
                .withInitialisationVector(IV_BASE64)
                .withDerived(true)
                .build();

        assertDeltaSecretEquals(expectedSecret, deltaClient.shareSecret(IDENTITY_ID, OTHER_IDENTITY_ID, SECRET_ID));

        verify(mockApiClient, times(1)).getIdentity(eq(expectedGetIdentityRequest));
        verify(mockApiClient, times(1)).getSecret(eq(expectedGetSecretRequest));
        verify(mockApiClient, times(1)).getSecretContent(eq(expectedGetSecretRequest));
        verify(mockApiClient, times(1)).shareSecret(eq(expectedShareSecretRequest));
        verify(mockCryptoService, times(1)).encrypt(eq(PLAIN_TEXT), eq(SECRET_KEY_A), eq(IV_SUPPLIER.get()));
        verify(mockCryptoService, times(1)).encryptKeyWithPublicKey(eq(SECRET_KEY_A), eq(CRYPTO_KEY_PAIR.getPublic()));
    }

    private void assertDeltaSecretEquals(DeltaSecret expected, DeltaSecret actual) {
        assertEquals(expected.getId(), actual.getId());
        assertEquals(expected.isDerived(), actual.isDerived());
        assertEquals(expected.getBaseSecretId(), actual.getBaseSecretId());
        assertEquals(expected.getCreatedBy(), actual.getCreatedBy());
        assertEquals(expected.getRsaKeyOwnerId(), actual.getRsaKeyOwnerId());
        assertEquals(expected.getCreatedDate(), actual.getCreatedDate());
        assertEquals(expected.getModifiedDate(), actual.getModifiedDate());
        assertEquals(expected.getEncryptionDetails().getInitialisationVector(),
                actual.getEncryptionDetails().getInitialisationVector());
        assertEquals(expected.getEncryptionDetails().getSymmetricKey(),
                actual.getEncryptionDetails().getSymmetricKey());
    }


    private void assertDeltaIdentityEquals(DeltaIdentity expected, DeltaIdentity actual) {
        assertEquals(expected.getId(), actual.getId());
        assertEquals(expected.getEncryptionPublicKeyBase64(), actual.getEncryptionPublicKeyBase64());
        assertEquals(expected.getExternalId(), actual.getExternalId());
        assertEquals(expected.getVersion(), actual.getVersion());
    }

    private DeltaSecret createDeltaSecretFromGetSecretResponse(GetSecretResponse response) {
        return DeltaSecret.builder(deltaClient, mockCryptoService)
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

    @Test
    public void shouldDeleteSecret() {
        SecretRequest expectedSecretRequest = new SecretRequest(IDENTITY_ID, SECRET_ID);

        deltaClient.deleteSecret(IDENTITY_ID, SECRET_ID);

        verify(mockApiClient).deleteSecret(expectedSecretRequest);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenDeletingSecretWithNullRequestorId() {
        deltaClient.deleteSecret(null, SECRET_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenDeletingSecretWithEmptyRequestorId() {
        deltaClient.deleteSecret("", SECRET_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenDeletingSecretWithInvalidRequestorId() {
        deltaClient.deleteSecret("asdfa-fdadf-23", SECRET_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenDeletingSecretWithNullSecretId() {
        deltaClient.deleteSecret(IDENTITY_ID, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenDeletingSecretWithEmptySecretrId() {
        deltaClient.deleteSecret(IDENTITY_ID, "");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenDeletingSecretWithInvalidSecretId() {
        deltaClient.deleteSecret(IDENTITY_ID, "asdfa-fdadf-23");
    }

    @Test
    public void shouldPassRequestWhenGetIdentitiesByMetadata() {
        GetIdentitiesByMetadataRequest expectedRequest = GetIdentitiesByMetadataRequest.builder(IDENTITY_ID)
                .withMetadata(METADATA)
                .withPage(2)
                .withPageSize(10)
                .build();

        deltaClient.getIdentitiesByMetadata(IDENTITY_ID, METADATA, 2, 10);

        verify(mockApiClient).getIdentitiesByMetadata(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetIdentitiesByMetadata() {
        when(mockApiClient.getIdentitiesByMetadata(any()))
                .thenReturn(ImmutableList.of(new GetIdentityResponse(IDENTITY_ID, "key", METADATA, EXTERNAL_ID, 5L)));

        List<DeltaIdentity> response = deltaClient.getIdentitiesByMetadata(IDENTITY_ID, METADATA, 2, 10);

        assertEquals(1, response.size());
        DeltaIdentity actualIdentity = response.get(0);
        assertEquals(IDENTITY_ID, actualIdentity.getId());
        assertEquals("key", actualIdentity.getEncryptionPublicKeyBase64());
        assertEquals(METADATA, actualIdentity.getMetadata());
        assertEquals(EXTERNAL_ID, actualIdentity.getExternalId());
        assertEquals(5L, actualIdentity.getVersion().longValue());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetIdentitiesByMetadataWithNullIdentityId() {
        deltaClient.getIdentitiesByMetadata(null, METADATA, 2, 10);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetIdentitiesByMetadataWithEmptyIdentityId() {
        deltaClient.getIdentitiesByMetadata(" ", METADATA, 2, 10);
    }

    @Test
    public void shouldPassRequestWhenGetEventsBySecretId() {
        GetEventsRequest expectedRequest = GetEventsRequest.builder(IDENTITY_ID)
                .withSecretId(SECRET_ID)
                .build();

        deltaClient.getEventsBySecretId(IDENTITY_ID, SECRET_ID);

        verify(mockApiClient).getEvents(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetEventsBySecretId() {
        GetEventResponse event = createGetEventResponse();

        when(mockApiClient.getEvents(any())).thenReturn(ImmutableList.of(event));

        List<DeltaEvent> actualEvents = deltaClient.getEventsBySecretId(IDENTITY_ID, SECRET_ID);

        assertEquals(1, actualEvents.size());
        DeltaEvent actualEvent = actualEvents.get(0);
        assertDeltaEvent(actualEvent);
    }

    private void assertDeltaEvent(DeltaEvent actualEvent) {
        assertEquals("eventId", actualEvent.getId());
        assertEquals("1.2.3.4", actualEvent.getSourceIp());
        assertEquals("now", actualEvent.getTimestamp());
        assertEquals("type", actualEvent.getEventName());
        assertEquals("host", actualEvent.getHost());
        assertEquals("baseSecretId", actualEvent.getEventDetails().getBaseSecretId());
        assertEquals(SECRET_ID, actualEvent.getEventDetails().getSecretId());
        assertEquals("requesterId", actualEvent.getEventDetails().getRequesterId());
        assertEquals(OTHER_IDENTITY_ID, actualEvent.getEventDetails().getRsaKeyOwnerId());
        assertEquals("secretCreatorId", actualEvent.getEventDetails().getSecretCreatorId());
    }

    private GetEventResponse createGetEventResponse() {
        GetEventResponse event = new GetEventResponse();
        EventDetails eventDetails = new EventDetails();
        eventDetails.setBaseSecretId("baseSecretId");
        eventDetails.setSecretId(SECRET_ID);
        eventDetails.setRequesterId("requesterId");
        eventDetails.setRsaKeyOwnerId(OTHER_IDENTITY_ID);
        eventDetails.setSecretOwnerId("secretCreatorId");
        event.setEventDetails(eventDetails);
        event.setId("eventId");
        event.setSourceIp("1.2.3.4");
        event.setTimestamp("now");
        event.setType("type");
        event.setHost("host");
        return event;
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsBySecretIdWithNullIdentityId() {
        deltaClient.getEventsBySecretId(null, SECRET_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsBySecretIdWithEmptyIdentityId() {
        deltaClient.getEventsBySecretId(" ", SECRET_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsBySecretIdWithNullSecretId() {
        deltaClient.getEventsBySecretId(IDENTITY_ID, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsBySecretIdWithEmptySecretId() {
        deltaClient.getEventsBySecretId(IDENTITY_ID, " ");
    }

    @Test
    public void shouldPassRequestWhenGetEventsByRsaKeyOwner() {
        GetEventsRequest expectedRequest = GetEventsRequest.builder(IDENTITY_ID)
                .withRsaKeyOwner(OTHER_IDENTITY_ID)
                .build();

        deltaClient.getEventsByRsaKeyOwner(IDENTITY_ID, OTHER_IDENTITY_ID);

        verify(mockApiClient).getEvents(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetEventsByRsaKeyOwner() {
        GetEventResponse event = createGetEventResponse();

        when(mockApiClient.getEvents(any())).thenReturn(ImmutableList.of(event));

        List<DeltaEvent> actualEvents = deltaClient.getEventsByRsaKeyOwner(IDENTITY_ID, OTHER_IDENTITY_ID);

        assertEquals(1, actualEvents.size());
        DeltaEvent actualEvent = actualEvents.get(0);
        assertDeltaEvent(actualEvent);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsByRsaKeyOwnerWithNullIdentityId() {
        deltaClient.getEventsByRsaKeyOwner(null, OTHER_IDENTITY_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsByRsaKeyOwnerWithEmptyIdentityId() {
        deltaClient.getEventsByRsaKeyOwner(" ", OTHER_IDENTITY_ID);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsByRsaKeyOwnerWithNullSecretId() {
        deltaClient.getEventsByRsaKeyOwner(IDENTITY_ID, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetEventsByRsaKeyOwnerWithEmptySecretId() {
        deltaClient.getEventsByRsaKeyOwner(IDENTITY_ID, " ");
    }

    @Test
    public void shouldPassRequestWhenGetDerivedSecretByBaseSecret() {
        GetDerivedSecretsRequest expectedRequest = GetDerivedSecretsRequest.builder(IDENTITY_ID)
                .withSecretId(SECRET_ID)
                .withPage(1)
                .withPageSize(2)
                .build();

        deltaClient.getDerivedSecretByBaseSecret(IDENTITY_ID, SECRET_ID, 1, 2);

        verify(mockApiClient).getDerivedSecrets(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetDerivedSecretByBaseSecret() {
        GetSecretsResponse secret = createGetSecretResponse();

        when(mockApiClient.getDerivedSecrets(any())).thenReturn(ImmutableList.of(secret));

        List<DeltaSecret> actualSecrets = deltaClient.getDerivedSecretByBaseSecret(IDENTITY_ID, SECRET_ID, 1, 2);

        assertEquals(1, actualSecrets.size());
        DeltaSecret actualSecret = actualSecrets.get(0);
        assertDeltaSecret(actualSecret, SecretType.DERIVED);
    }

    private GetSecretsResponse createGetSecretResponse() {
        GetSecretsResponse response = new GetSecretsResponse();

        response.setId(SECRET_ID);
        response.setCreatedBy("createdBy");
        response.setRsaKeyOwner("rsaKeyOwner");
        response.setCreated("created");
        response.setBaseSecret("baseSecret");
        response.setMetadata(METADATA);

        return response;
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetDerivedSecretByBaseSecretWithEmptyIdentityId() {
        deltaClient.getDerivedSecretByBaseSecret(" ", SECRET_ID, 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetDerivedSecretByBaseSecretWithNullIdentityId() {
        deltaClient.getDerivedSecretByBaseSecret(null, SECRET_ID, 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetDerivedSecretByBaseSecretWithEmptyBaseSecretId() {
        deltaClient.getDerivedSecretByBaseSecret(IDENTITY_ID, " ", 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetDerivedSecretByBaseSecretWithNullBaseSecretId() {
        deltaClient.getDerivedSecretByBaseSecret(IDENTITY_ID, null, 1, 2);
    }

    @Test
    public void shouldPassRequestWhenGetBaseSecretsByMetadata() {
        GetBaseSecretsByMetadataRequest expectedRequest = GetBaseSecretsByMetadataRequest.builder(IDENTITY_ID)
                .withCreatedBy(OTHER_IDENTITY_ID)
                .withMetadata(METADATA)
                .withPage(1)
                .withPageSize(2)
                .build();

        deltaClient.getBaseSecretsByMetadata(IDENTITY_ID, OTHER_IDENTITY_ID, METADATA, 1, 2);

        verify(mockApiClient).getBaseSecretsByMetadata(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetBaseSecretsByMetadata() {
        GetSecretsResponse secret = createGetSecretResponse();

        when(mockApiClient.getBaseSecretsByMetadata(any())).thenReturn(ImmutableList.of(secret));

        List<DeltaSecret> actualSecrets = deltaClient.getBaseSecretsByMetadata(IDENTITY_ID, OTHER_IDENTITY_ID, METADATA, 1, 2);

        assertEquals(1, actualSecrets.size());
        DeltaSecret actualSecret = actualSecrets.get(0);
        assertDeltaSecret(actualSecret, SecretType.BASE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetBaseSecretsByMetadataWithEmptyIdentityId() {
        deltaClient.getBaseSecretsByMetadata(" ", OTHER_IDENTITY_ID, METADATA, 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetBaseSecretsByMetadataWithNullIdentityId() {
        deltaClient.getBaseSecretsByMetadata(null, OTHER_IDENTITY_ID, METADATA, 1, 2);
    }

    private void assertDeltaSecret(DeltaSecret actualSecret, SecretType secretType) {
        SecretType actualSecretType = actualSecret.isDerived() ? SecretType.DERIVED : SecretType.BASE;
        assertEquals(secretType, actualSecretType);
        assertEquals(SECRET_ID, actualSecret.getId());
        assertEquals("createdBy", actualSecret.getCreatedBy());
        assertEquals("rsaKeyOwner", actualSecret.getRsaKeyOwnerId());
        assertEquals("created", actualSecret.getCreatedDate());
        assertEquals("baseSecret", actualSecret.getBaseSecretId());
        assertEquals(METADATA, actualSecret.getMetadata());
    }

    @Test
    public void shouldPassRequestWhenGetDerivedSecretsByMetadata() {
        GetDerivedSecretsByMetadataRequest expectedRequest = GetDerivedSecretsByMetadataRequest.builder(IDENTITY_ID)
                .withRsaKeyOwnerId(OTHER_IDENTITY_ID)
                .withMetadata(METADATA)
                .withPage(1)
                .withPageSize(2)
                .build();

        deltaClient.getDerivedSecretsByMetadata(IDENTITY_ID, OTHER_IDENTITY_ID, METADATA, 1, 2);

        verify(mockApiClient).getDerivedSecretsByMetadata(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetDerivedSecretsByMetadata() {
        GetSecretsResponse secret = createGetSecretResponse();

        when(mockApiClient.getDerivedSecretsByMetadata(any())).thenReturn(ImmutableList.of(secret));

        List<DeltaSecret> actualSecrets = deltaClient.getDerivedSecretsByMetadata(IDENTITY_ID, OTHER_IDENTITY_ID, METADATA, 1, 2);

        assertEquals(1, actualSecrets.size());
        DeltaSecret actualSecret = actualSecrets.get(0);
        assertDeltaSecret(actualSecret, SecretType.DERIVED);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetDerivedSecretsByMetadataWithEmptyIdentityId() {
        deltaClient.getDerivedSecretsByMetadata(" ", OTHER_IDENTITY_ID, METADATA, 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetDerivedSecretsByMetadataWithNullIdentityId() {
        deltaClient.getDerivedSecretsByMetadata(null, OTHER_IDENTITY_ID, METADATA, 1, 2);
    }

    @Test
    public void shouldPassRequestWhenGetSharedSecrets() {
        GetSecretsRequest expectedRequest = GetSecretsRequest.builder(IDENTITY_ID)
                .withPage(1)
                .withPageSize(2)
                .build();

        deltaClient.getSharedSecrets(IDENTITY_ID, 1, 2);

        verify(mockApiClient).getSharedSecrets(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetSharedSecrets() {
        GetSecretsResponse secret = createGetSecretResponse();

        when(mockApiClient.getSharedSecrets(any())).thenReturn(ImmutableList.of(secret));

        List<DeltaSecret> actualSecrets = deltaClient.getSharedSecrets(IDENTITY_ID, 1, 2);

        assertEquals(1, actualSecrets.size());
        DeltaSecret actualSecret = actualSecrets.get(0);
        assertDeltaSecret(actualSecret, SecretType.DERIVED);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetSharedSecretsWithEmptyIdentityId() {
        deltaClient.getSharedSecrets(" ", 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetSharedSecretsWithNullIdentityId() {
        deltaClient.getSharedSecrets(null, 1, 2);
    }

    @Test
    public void shouldPassRequestWhenGetSecretsSharedWithMe() {
        GetSecretsRequest expectedRequest = GetSecretsRequest.builder(IDENTITY_ID)
                .withPage(1)
                .withPageSize(2)
                .build();

        deltaClient.getSecretsSharedWithMe(IDENTITY_ID, 1, 2);

        verify(mockApiClient).getSecretsSharedWithMe(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetSecretsSharedWithMe() {
        GetSecretsResponse secret = createGetSecretResponse();

        when(mockApiClient.getSecretsSharedWithMe(any())).thenReturn(ImmutableList.of(secret));

        List<DeltaSecret> actualSecrets = deltaClient.getSecretsSharedWithMe(IDENTITY_ID, 1, 2);

        assertEquals(1, actualSecrets.size());
        DeltaSecret actualSecret = actualSecrets.get(0);
        assertDeltaSecret(actualSecret, SecretType.DERIVED);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetSecretsSharedWithMeWithEmptyIdentityId() {
        deltaClient.getSecretsSharedWithMe(" ", 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetSecretsSharedWithMeWithNullIdentityId() {
        deltaClient.getSecretsSharedWithMe(null, 1, 2);
    }

    @Test
    public void shouldPassRequestWhenGetOwnedSecrets() {
        GetSecretsRequest expectedRequest = GetSecretsRequest.builder(IDENTITY_ID)
                .withPage(1)
                .withPageSize(2)
                .build();

        deltaClient.getOwnedSecrets(IDENTITY_ID, 1, 2);

        verify(mockApiClient).getOwnedSecrets(expectedRequest);
    }

    @Test
    public void shouldParseResponseWhenGetOwnedSecrets() {
        GetSecretsResponse secret = createGetSecretResponse();

        when(mockApiClient.getOwnedSecrets(any())).thenReturn(ImmutableList.of(secret));

        List<DeltaSecret> actualSecrets = deltaClient.getOwnedSecrets(IDENTITY_ID, 1, 2);

        assertEquals(1, actualSecrets.size());
        DeltaSecret actualSecret = actualSecrets.get(0);
        assertDeltaSecret(actualSecret, SecretType.BASE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetOwnedSecretsWithEmptyIdentityId() {
        deltaClient.getOwnedSecrets(" ", 1, 2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenGetOwnedSecretsWithNullIdentityId() {
        deltaClient.getOwnedSecrets(null, 1, 2);
    }
}
