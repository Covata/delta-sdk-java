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

import com.covata.delta.sdk.api.common.EncryptionDetails;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;

import static com.google.common.base.Preconditions.checkArgument;

@JsonPropertyOrder(alphabetic = true)
public class CreateSecretRequest {

    @JsonIgnore
    private final String identityId;

    @JsonProperty("content")
    private final String content;

    @JsonProperty("encryptionDetails")
    private final EncryptionDetails encryptionDetails;

    public CreateSecretRequest(String identityId, String content,
                               EncryptionDetails encryptionDetails) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(content), "content must be specified");
        checkArgument(encryptionDetails != null, "encryption detail must be specified");

        this.identityId = identityId;
        this.content = content;
        this.encryptionDetails = encryptionDetails;
    }

    public String getContent() {
        return content;
    }

    public EncryptionDetails getEncryptionDetails() {
        return encryptionDetails;
    }

    public String getIdentityId() {
        return identityId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CreateSecretRequest that = (CreateSecretRequest) o;
        return Objects.equal(identityId, that.identityId) &&
                Objects.equal(content, that.content) &&
                Objects.equal(encryptionDetails, that.encryptionDetails);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, content, encryptionDetails);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("identityId", identityId)
                .add("content", content)
                .add("encryptionDetails", encryptionDetails)
                .toString();
    }

    public static CreateSecretRequestBuilder builder(String requestorId) {
        return new CreateSecretRequestBuilder(requestorId);
    }

    public static final class CreateSecretRequestBuilder {
        private final String identityId;

        private String content;

        private EncryptionDetails encryptionDetails;

        private CreateSecretRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public CreateSecretRequestBuilder withContent(String content) {
            this.content = content;
            return this;
        }

        public CreateSecretRequestBuilder withEncryptionDetails(EncryptionDetails encryptionDetails) {
            this.encryptionDetails = encryptionDetails;
            return this;
        }

        public CreateSecretRequestBuilder withEncryptionDetails(String symmetricKey,
                                                                byte[] initialisationVector) {
            this.encryptionDetails = new EncryptionDetails(
                    symmetricKey, BaseEncoding.base64().encode(initialisationVector));
            return this;
        }

        public CreateSecretRequestBuilder withEncryptionDetails(String symmetricKey,
                                                                String initialisationVector) {
            this.encryptionDetails = new EncryptionDetails(
                    symmetricKey, initialisationVector);
            return this;
        }

        public CreateSecretRequest build() {
            return new CreateSecretRequest(identityId, content, encryptionDetails);
        }
    }
}
