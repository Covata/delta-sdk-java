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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

@JsonPropertyOrder(alphabetic = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateIdentityRequest {

    @JsonProperty("signingPublicKey")
    private final String signingPublicKey;

    @JsonProperty("cryptoPublicKey")
    private final String encryptionPublicKey;

    @JsonProperty("externalId")
    private final String externalId;

    @JsonProperty("metadata")
    private final Map<String, String> metadata;

    public CreateIdentityRequest(String signingPublicKey, String encryptionPublicKey,
                                 String externalId, Map<String, String> metadata) {
        checkArgument(!Strings.isNullOrEmpty(signingPublicKey), "signing public key must be specified");
        checkArgument(!Strings.isNullOrEmpty(encryptionPublicKey), "encryption public key must be specified");
        this.signingPublicKey = signingPublicKey;
        this.encryptionPublicKey = encryptionPublicKey;
        this.externalId = externalId;
        this.metadata = metadata != null ? ImmutableMap.copyOf(metadata) : null;
    }

    public String getSigningPublicKey() {
        return signingPublicKey;
    }

    public String getEncryptionPublicKey() {
        return encryptionPublicKey;
    }

    public String getExternalId() {
        return externalId;
    }

    public Map<String, String> getMetadata() {
        return metadata != null ? ImmutableMap.copyOf(metadata) : null;
    }

    public static CreateIdentityRequestBuilder builder(String signingPublicKey,
                                                       String encryptionPublicKey) {
        return new CreateIdentityRequestBuilder(signingPublicKey, encryptionPublicKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CreateIdentityRequest request = (CreateIdentityRequest) o;
        return Objects.equal(signingPublicKey, request.signingPublicKey) &&
                Objects.equal(encryptionPublicKey, request.encryptionPublicKey) &&
                Objects.equal(externalId, request.externalId) &&
                Objects.equal(metadata, request.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(signingPublicKey, encryptionPublicKey, externalId, metadata);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("signingPublicKey", signingPublicKey)
                .add("encryptionPublicKey", encryptionPublicKey)
                .add("externalId", externalId)
                .add("metadata", metadata)
                .toString();
    }

    public static final class CreateIdentityRequestBuilder {
        private final String signingPublicKey;

        private final String encryptionPublicKey;

        private String externalId;

        private Map<String, String> metadata;

        private CreateIdentityRequestBuilder(String signingPublicKey,
                                             String encryptionPublicKey) {
            this.signingPublicKey = signingPublicKey;
            this.encryptionPublicKey = encryptionPublicKey;
        }

        public CreateIdentityRequestBuilder withExternalId(String externalId) {
            this.externalId = externalId;
            return this;
        }

        public CreateIdentityRequestBuilder withMetadata(Map<String, String> metadata) {
            this.metadata = metadata;
            return this;
        }

        public CreateIdentityRequest build() {
            return new CreateIdentityRequest(
                    signingPublicKey, encryptionPublicKey, externalId, metadata);
        }
    }
}
