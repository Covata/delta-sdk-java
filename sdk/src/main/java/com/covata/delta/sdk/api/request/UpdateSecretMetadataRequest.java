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

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

public class UpdateSecretMetadataRequest {

    private final String identityId;

    private final String secretId;

    private final Map<String, String> metadata;

    private final Long version;

    public UpdateSecretMetadataRequest(String identityId,
                                       String secretId,
                                       Long version,
                                       Map<String, String> metadata) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(secretId), "secret id to update must be specified");
        checkArgument(version != null, "version number must be specified");
        checkArgument(metadata != null, "metadata must be specified");
        this.identityId = identityId;
        this.secretId = secretId;
        this.metadata = ImmutableMap.copyOf(metadata);
        this.version = version;
    }

    public String getIdentityId() {
        return identityId;
    }

    public String getSecretId() {
        return secretId;
    }
    
    public long getVersion() {
        return version;
    }

    public Map<String, String> getMetadata() {
        return metadata;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UpdateSecretMetadataRequest that = (UpdateSecretMetadataRequest) o;
        return Objects.equal(identityId, that.identityId) &&
                Objects.equal(secretId, that.secretId) &&
                Objects.equal(metadata, that.metadata) &&
                Objects.equal(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, secretId, metadata, version);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("identityId", identityId)
                .add("secretId", secretId)
                .add("metadata", metadata)
                .add("version", version)
                .toString();
    }

    public static UpdateSecretMetadataRequestBuilder builder(String requestorId) {
        return new UpdateSecretMetadataRequestBuilder(requestorId);
    }

    public static final class UpdateSecretMetadataRequestBuilder {
        private final String identityId;

        private String secretId;

        private Map<String, String> metadata;

        private Long version;

        private UpdateSecretMetadataRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public UpdateSecretMetadataRequestBuilder withSecretId(String secretId) {
            this.secretId = secretId;
            return this;
        }

        public UpdateSecretMetadataRequestBuilder withMetadata(Map<String, String> metadata) {
            this.metadata = metadata;
            return this;
        }

        public UpdateSecretMetadataRequestBuilder withVersion(long version) {
            this.version = version;
            return this;
        }

        public UpdateSecretMetadataRequest build() {
            return new UpdateSecretMetadataRequest(identityId, secretId, version, metadata);
        }
    }
}
