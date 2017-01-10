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
import com.google.common.collect.ImmutableMap;
import com.google.common.io.BaseEncoding;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.util.Collection;
import java.util.Map;
import java.util.stream.IntStream;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyCollection;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class DeltaSecretTest {

    private static final String DECRYPTED_CONTENT = "decrypted";

    private static final String ENCRYPTED_CONTENT = "encrypted";

    private static final String SECRET_ID = "mock-secret-id";

    private static final String IDENTITY_ID = "mock-identity-id";

    private static final String SYMMETRIC_KEY = "key";

    private static final String INITIALISATION_VECTOR = "iv";

    private static final long METADATA_VERSION = 2L;

    private static final Map<String, String> METADATA = ImmutableMap.of("name", "DSS");

    private static final int NUM_REPETITIONS = 10;

    private static final String PRECONDITION_FAILED = "Precondition Failed";

    private DeltaClient mockDeltaClient;

    private CryptoService mockCryptoService;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @SuppressWarnings("unchecked")
    @Before
    public void init() {
        mockDeltaClient = mock(DeltaClient.class);

        when(mockDeltaClient.getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenReturn(new GetSecretMetadataResponse(METADATA, METADATA_VERSION));

        mockCryptoService = mock(CryptoService.class);
        when(mockCryptoService.decrypt(
                eq(ENCRYPTED_CONTENT), eq(SYMMETRIC_KEY),
                eq(BaseEncoding.base64().decode(INITIALISATION_VECTOR)), eq(IDENTITY_ID)))
                .thenReturn(DECRYPTED_CONTENT);

        doThrow(new DeltaServiceException(PRECONDITION_FAILED))
                .when(mockDeltaClient)
                .addSecretMetadata(
                        eq(IDENTITY_ID), eq(SECRET_ID), not(eq(METADATA_VERSION)), anyMap());

        doThrow(new DeltaServiceException(PRECONDITION_FAILED))
                .when(mockDeltaClient)
                .removeSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID), not(eq(METADATA_VERSION)), anyCollection());
    }

    @Test
    public void shouldLazilyGetTheEncryptedContent() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withSymmetricKey(SYMMETRIC_KEY)
                .withInitialisationVector(INITIALISATION_VECTOR)
                .build();

        when(mockDeltaClient.getSecretContentEncrypted(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenReturn(ENCRYPTED_CONTENT);


        execute(() -> assertThat(deltaSecret.getContent(), is(DECRYPTED_CONTENT)));

        verify(mockDeltaClient, times(1))
                .getSecretContentEncrypted(eq(IDENTITY_ID), eq(SECRET_ID));

        verify(mockCryptoService, times(NUM_REPETITIONS))
                .decrypt(eq(ENCRYPTED_CONTENT),
                        eq(SYMMETRIC_KEY),
                        eq(BaseEncoding.base64().decode(INITIALISATION_VECTOR)),
                        eq(IDENTITY_ID));
    }

    @Test
    public void shouldUseProvidedEncryptionDetailsWhenKeyAndIVAreProvided() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withSymmetricKey(SYMMETRIC_KEY)
                .withInitialisationVector(INITIALISATION_VECTOR)
                .build();

        assertThat(deltaSecret.getEncryptionDetails().getSymmetricKey(),
                is(SYMMETRIC_KEY));
        assertThat(deltaSecret.getEncryptionDetails().getInitialisationVector(),
                is(INITIALISATION_VECTOR));

        verifyZeroInteractions(mockDeltaClient);
    }

    @Test
    public void shouldLazilyRequestEncryptionDetailsWhenKeyAndIVAreNotProvided() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        DeltaSecret deltaSecretWithEncryptionDetails = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withInitialisationVector(INITIALISATION_VECTOR)
                .withSymmetricKey(SYMMETRIC_KEY)
                .build();

        when(mockDeltaClient.getSecret(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenReturn(deltaSecretWithEncryptionDetails);
        assertThat(deltaSecret.getEncryptionDetails().getSymmetricKey(),
                is(SYMMETRIC_KEY));
        assertThat(deltaSecret.getEncryptionDetails().getInitialisationVector(),
                is(INITIALISATION_VECTOR));

        verify(mockDeltaClient, times(1)).getSecret(eq(IDENTITY_ID), eq(SECRET_ID));
    }


    @Test
    public void shouldUseProvidedMetadata() {

        Map<String, String> metadata = ImmutableMap.of("key", "value");

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withMetadata(metadata)
                .build();

        execute(() -> assertThat(deltaSecret.getMetadata(), is(metadata)));

        verifyZeroInteractions(mockDeltaClient);
    }

    @Test
    public void shouldLazilyGetMetadata() {

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        when(mockDeltaClient.getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenReturn(new GetSecretMetadataResponse(METADATA, METADATA_VERSION));

        execute(() -> assertThat(deltaSecret.getMetadata(), is(METADATA)));

        verify(mockDeltaClient, times(1))
                .getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID));
    }

    @Test
    public void shouldSynchronizeMetadata() {
        Map<String, String> providedMetadata = ImmutableMap.of("key", "value");

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withMetadata(providedMetadata)
                .build();

        when(mockDeltaClient.getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenReturn(new GetSecretMetadataResponse(METADATA, METADATA_VERSION));
        
        assertThat(deltaSecret.getMetadata(), is(providedMetadata));
        deltaSecret.synchronizeMetadata();
        execute(() -> assertThat(deltaSecret.getMetadata(), is(METADATA)));

        verify(mockDeltaClient, times(1))
                .getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID));
    }

    @Test(expected = DeltaServiceException.class)
    public void shouldThrowDeltaServiceExceptionOnFailGetMetadata() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        when(mockDeltaClient.getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenThrow(new DeltaServiceException("failed"));

        deltaSecret.getMetadata();
    }

    @Test(expected = DeltaServiceException.class)
    public void shouldThrowDeltaServiceExceptionOnFailGetContent() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withSymmetricKey(SYMMETRIC_KEY)
                .withInitialisationVector(INITIALISATION_VECTOR)
                .build();

        when(mockDeltaClient.getSecretContentEncrypted(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenThrow(new DeltaServiceException("failed"));

        deltaSecret.getContent();
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowDeltaClientExceptionOnFailDecryptingContent() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withSymmetricKey(SYMMETRIC_KEY)
                .withInitialisationVector(INITIALISATION_VECTOR)
                .build();

        when(mockDeltaClient.getSecretContentEncrypted(eq(IDENTITY_ID), eq(SECRET_ID)))
                .thenReturn(ENCRYPTED_CONTENT);

        when(mockCryptoService.decrypt(anyString(), anyString(), any(), anyString()))
                .thenThrow(new DeltaClientException("failed"));

        deltaSecret.getContent();
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldSynchronizeMetadataOnAddMetadata() {
        String key = "key";
        String value = "value";
        Map<String, String> expectedMetadata = ImmutableMap.of(key, value);

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withMetadataVersion(METADATA_VERSION)
                .build();

        ArgumentCaptor<Map> argumentCaptor = ArgumentCaptor.forClass(Map.class);

        doNothing().when(mockDeltaClient).addSecretMetadata(
                eq(IDENTITY_ID), eq(SECRET_ID), eq(METADATA_VERSION), argumentCaptor.capture());

        deltaSecret.addMetadata(key, value);
        assertThat(argumentCaptor.getValue(), is(expectedMetadata));
        verify(mockDeltaClient, times(1)).getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldSynchronizeMetadataOnAddMetadataMap() {
        String key = "key";
        String value = "value";
        Map<String, String> expectedMetadata = ImmutableMap.of(key, value);

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withMetadataVersion(METADATA_VERSION)
                .build();

        ArgumentCaptor<Map> argumentCaptor = ArgumentCaptor.forClass(Map.class);

        doNothing().when(mockDeltaClient).addSecretMetadata(
                eq(IDENTITY_ID), eq(SECRET_ID), eq(METADATA_VERSION), argumentCaptor.capture());

        deltaSecret.addMetadata(ImmutableMap.of(key, value));
        assertThat(argumentCaptor.getValue(), is(expectedMetadata));
        verify(mockDeltaClient, times(1)).getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID));
    }

    @Test
    public void shouldFailOnAddMetadataWhenVersionIsNotUpToDate() {
        expectedException.expect(DeltaServiceException.class);
        expectedException.expectMessage(PRECONDITION_FAILED);

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        deltaSecret.addMetadata(ImmutableMap.of("key", "value"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldUpdateMetadataVersionAndSucceedOnSubsequentAddMetadata() {

        final int expectedRetries = 2;

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        int retries = DeltaModelTestUtil.getRetriesUntilFirstSuccess(expectedRetries,
                () -> deltaSecret.addMetadata(METADATA),
                e -> PRECONDITION_FAILED.equals(e.getMessage()));

        assertThat(retries, is(expectedRetries));
        verify(mockDeltaClient, times(expectedRetries)).getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID));
    }

    @Test
    public void shouldSucceedWhenAddMetadataAfterSynchronize() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        deltaSecret.synchronizeMetadata();
        deltaSecret.addMetadata(ImmutableMap.of("key", "value"));
    }

    @Test
    public void shouldSucceedWhenRemoveMetadataAfterSynchronize() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        deltaSecret.synchronizeMetadata();
        deltaSecret.removeMetadata("name");
    }

    @Test
    public void shouldFailOnRemoveMetadataWhenVersionIsNotUpToDate() {
        expectedException.expect(DeltaServiceException.class);
        expectedException.expectMessage("Precondition Failed");

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        deltaSecret.removeMetadata("name");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldSynchronizeMetadataOnRemoveMetadata() {
        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .withMetadataVersion(METADATA_VERSION)
                .build();

        ArgumentCaptor<Collection> argumentCaptor = ArgumentCaptor.forClass(Collection.class);

        doNothing().when(mockDeltaClient).removeSecretMetadata(
                eq(IDENTITY_ID), eq(SECRET_ID), eq(METADATA_VERSION), argumentCaptor.capture());

        deltaSecret.removeMetadata("name");
        assertThat(argumentCaptor.getValue().size(), is(1));
        assertTrue(argumentCaptor.getValue().contains("name"));
        verify(mockDeltaClient, times(1)).getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldUpdateMetadataVersionAndSucceedOnSubsequentRemoveMetadata() {
        final int expectedRetries = 2;

        DeltaSecret deltaSecret = DeltaSecret.builder(mockDeltaClient, mockCryptoService)
                .withId(SECRET_ID)
                .withCreatedBy(IDENTITY_ID)
                .withRsaKeyOwnerId(IDENTITY_ID)
                .build();

        int retries = DeltaModelTestUtil.getRetriesUntilFirstSuccess(expectedRetries,
                () -> deltaSecret.removeMetadata("name"),
                e -> PRECONDITION_FAILED.equals(e.getMessage()));

        assertThat(retries, is(expectedRetries));
        verify(mockDeltaClient, times(expectedRetries)).getSecretMetadata(eq(IDENTITY_ID), eq(SECRET_ID));
    }

    private void execute(Runnable task) {
        IntStream.range(0, NUM_REPETITIONS).forEach(i -> task.run());
    }
}
