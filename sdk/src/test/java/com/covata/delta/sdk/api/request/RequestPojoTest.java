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

package com.covata.delta.sdk.api.request;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.Test;

public class RequestPojoTest {

    @Test
    public void equalsContractGetSecretsRequest() {
        EqualsVerifier.forClass(GetSecretsRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractGetBaseSecretsByMetadataRequest() {
        EqualsVerifier.forClass(GetBaseSecretsByMetadataRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractGetDerivedSecretsRequest() {
        EqualsVerifier.forClass(GetDerivedSecretsRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractShareSecretRequest() {
        EqualsVerifier.forClass(ShareSecretRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractSecretRequest() {
        EqualsVerifier.forClass(SecretRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractGetIdentityRequest() {
        EqualsVerifier.forClass(GetIdentityRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractCreateSecretRequest() {
        EqualsVerifier.forClass(CreateSecretRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractCreateIdentityRequest() {
        EqualsVerifier.forClass(CreateIdentityRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractUpdateSecretMetadataRequest() {
        EqualsVerifier.forClass(UpdateSecretMetadataRequest.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void equalsContractUpdateIdentityMetadataRequest() {
        EqualsVerifier.forClass(UpdateIdentityMetadataRequest.class)
                .usingGetClass()
                .verify();
    }
}
