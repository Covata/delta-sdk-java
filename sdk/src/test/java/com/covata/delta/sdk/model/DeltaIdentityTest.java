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
import com.covata.delta.sdk.exception.DeltaServiceException;
import com.google.common.collect.ImmutableMap;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.IntStream;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.Matchers.anyCollection;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class DeltaIdentityTest {

    private static final String IDENTITY_ID = "mock-identity-id";

    private static final long METADATA_VERSION = 2L;

    private static final Map<String, String> METADATA = ImmutableMap.of("name", "DSS");

    private static final int NUM_REPETITIONS = 10;

    private static final String PRECONDITION_FAILED = "Precondition Failed";

    private DeltaClient mockDeltaClient;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @SuppressWarnings("unchecked")
    @Before
    public void init() {
        mockDeltaClient = mock(DeltaClient.class);

        when(mockDeltaClient.getIdentity(eq(IDENTITY_ID)))
                .thenReturn(DeltaIdentity.builder(mockDeltaClient)
                        .withId(IDENTITY_ID)
                        .withMetadata(METADATA)
                        .withVersion(METADATA_VERSION)
                        .build());

        doThrow(new DeltaServiceException(PRECONDITION_FAILED))
                .when(mockDeltaClient)
                .addIdentityMetadata(
                        eq(IDENTITY_ID), not(eq(METADATA_VERSION)), anyMap());

        doThrow(new DeltaServiceException(PRECONDITION_FAILED))
                .when(mockDeltaClient)
                .removeIdentityMetadata(
                        eq(IDENTITY_ID), not(eq(METADATA_VERSION)), anyCollection());
    }

    @Test
    public void shouldUseProvidedMetadata() {

        Map<String, String> metadata = ImmutableMap.of("key", "value");

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .withMetadata(metadata)
                .build();

        execute(() -> assertThat(deltaIdentity.getMetadata(), is(metadata)));

        verifyZeroInteractions(mockDeltaClient);
    }

    @Test
    public void shouldLazilyGetMetadata() {
        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        execute(() -> assertThat(deltaIdentity.getMetadata(), is(METADATA)));

        verify(mockDeltaClient, times(1)).getIdentity(eq(IDENTITY_ID));
    }

    @Test(expected = DeltaServiceException.class)
    public void shouldThrowDeltaServiceExceptionOnFailGetMetadata() {
        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        when(mockDeltaClient.getIdentity(eq(IDENTITY_ID)))
                .thenThrow(new DeltaServiceException("failed"));

        deltaIdentity.getMetadata();
    }

    @Test
    public void shouldSynchronizeMetadata() {
        Map<String, String> providedMetadata = ImmutableMap.of("key", "value");

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .withVersion(1L)
                .withMetadata(providedMetadata)
                .build();

        assertThat(deltaIdentity.getMetadata(), is(providedMetadata));
        deltaIdentity.synchronizeMetadata();
        execute(() -> assertThat(deltaIdentity.getMetadata(), is(METADATA)));
        execute(() -> assertThat(deltaIdentity.getVersion(), is(METADATA_VERSION)));

        verify(mockDeltaClient, times(1)).getIdentity(eq(IDENTITY_ID));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldSynchronizeMetadataOnAddMetadata() {
        String key = "key";
        String value = "value";
        Map<String, String> expectedMetadata = ImmutableMap.of(key, value);

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .withVersion(METADATA_VERSION)
                .build();

        ArgumentCaptor<Map> argumentCaptor = ArgumentCaptor.forClass(Map.class);

        doNothing().when(mockDeltaClient).addIdentityMetadata(
                eq(IDENTITY_ID), eq(METADATA_VERSION), argumentCaptor.capture());

        deltaIdentity.addMetadata(key, value);
        assertThat(argumentCaptor.getValue(), is(expectedMetadata));
        verify(mockDeltaClient, times(1)).getIdentity(eq(IDENTITY_ID));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldSynchronizeMetadataOnAddMetadataMap() {
        String key = "key";
        String value = "value";
        Map<String, String> expectedMetadata = ImmutableMap.of(key, value);

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .withVersion(METADATA_VERSION)
                .build();

        ArgumentCaptor<Map> argumentCaptor = ArgumentCaptor.forClass(Map.class);

        doNothing().when(mockDeltaClient).addIdentityMetadata(
                eq(IDENTITY_ID), eq(METADATA_VERSION), argumentCaptor.capture());

        deltaIdentity.addMetadata(ImmutableMap.of(key, value));
        assertThat(argumentCaptor.getValue(), is(expectedMetadata));
        verify(mockDeltaClient, times(1)).getIdentity(eq(IDENTITY_ID));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shouldSynchronizeMetadataOnRemoveMetadata() {
        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .withVersion(METADATA_VERSION)
                .build();

        ArgumentCaptor<Collection> argumentCaptor = ArgumentCaptor.forClass(Collection.class);

        doNothing().when(mockDeltaClient).removeIdentityMetadata(
                eq(IDENTITY_ID), eq(METADATA_VERSION), argumentCaptor.capture());

        deltaIdentity.removeMetadata("name");
        assertEquals(argumentCaptor.getValue().size(), 1);
        assertTrue(argumentCaptor.getValue().contains("name"));
        verify(mockDeltaClient, times(1)).getIdentity(eq(IDENTITY_ID));
    }

    @Test
    public void shouldFailOnAddMetadataWhenVersionIsNotUpToDate() {
        expectedException.expect(DeltaServiceException.class);
        expectedException.expectMessage(PRECONDITION_FAILED);

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        deltaIdentity.addMetadata(ImmutableMap.of("key", "value"));
    }

    @Test
    public void shouldFailOnRemoveMetadataWhenVersionIsNotUpToDate() {
        expectedException.expect(DeltaServiceException.class);
        expectedException.expectMessage(PRECONDITION_FAILED);

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        deltaIdentity.removeMetadata("key");
    }

    @Test
    public void shouldSucceedWhenAddMetadataAfterSynchronize() {
        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        deltaIdentity.synchronizeMetadata();
        deltaIdentity.addMetadata(ImmutableMap.of("key", "value"));
    }

    @Test
    public void shouldSucceedWhenRemoveMetadataAfterSynchronize() {
        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        deltaIdentity.synchronizeMetadata();
        deltaIdentity.removeMetadata("key");
    }

    @Test
    public void shouldUpdateMetadataVersionAndSucceedOnSubsequentAddMetadata() {

        final int expectedRetries = 2;

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        int retries = DeltaModelTestUtil.getRetriesUntilFirstSuccess(expectedRetries,
                () -> deltaIdentity.addMetadata(METADATA),
                e -> PRECONDITION_FAILED.equals(e.getMessage()));

        assertThat(retries, is(expectedRetries));
        verify(mockDeltaClient, times(expectedRetries)).getIdentity(eq(IDENTITY_ID));
    }

    @Test
    public void shouldUpdateMetadataVersionAndSucceedOnSubsequentRemoveMetadata() {

        final int expectedRetries = 2;

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        int retries = DeltaModelTestUtil.getRetriesUntilFirstSuccess(expectedRetries,
                () -> deltaIdentity.removeMetadata("name"),
                e -> PRECONDITION_FAILED.equals(e.getMessage()));

        assertThat(retries, is(expectedRetries));
        verify(mockDeltaClient, times(expectedRetries)).getIdentity(eq(IDENTITY_ID));
    }

    @Test
    public void shouldRetrieveDerivedSecretByMetadata() {
        int page = 1;
        int pageSize = 1;

        DeltaIdentity deltaIdentity = DeltaIdentity.builder(mockDeltaClient)
                .withId(IDENTITY_ID)
                .build();

        when(mockDeltaClient.getDerivedSecretsByMetadata(
                eq(deltaIdentity.getId()),
                eq(deltaIdentity.getId()),
                eq(METADATA),
                eq(page),
                eq(pageSize))).thenReturn(Collections.emptyList());

        deltaIdentity.retrieveDerivedSecrets(METADATA, page, pageSize);
        verify(mockDeltaClient, times(1))
                .getDerivedSecretsByMetadata(
                        eq(deltaIdentity.getId()),
                        eq(deltaIdentity.getId()),
                        eq(METADATA),
                        eq(page),
                        eq(pageSize));
    }

    private void execute(Runnable task) {
        IntStream.range(0, NUM_REPETITIONS).forEach(i -> task.run());
    }
}
