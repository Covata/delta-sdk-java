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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

public class UpdateIdentityMetadataRequest {

    @JsonIgnore
    private final String identityId;

    @JsonIgnore
    private final String identityIdToUpdate;

    @JsonIgnore
    private final Long version;

    @JsonProperty("metadata")
    private final Map<String, String> metadata;

    public UpdateIdentityMetadataRequest(String identityId,
                                         String identityIdToUpdate,
                                         Long version,
                                         Map<String, String> metadata) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(identityIdToUpdate), "identity id to update must be specified");
        checkArgument(version != null, "version number must be specified");
        checkArgument(metadata != null, "metadata must be specified");
        this.identityId = identityId;
        this.identityIdToUpdate = identityIdToUpdate;
        this.version = version;
        this.metadata = ImmutableMap.copyOf(metadata);
    }

    public Map<String, String> getMetadata() {
        return metadata;
    }

    public String getIdentityId() {
        return identityId;
    }

    public String getIdentityIdToUpdate() {
        return identityIdToUpdate;
    }

    public long getVersion() {
        return version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UpdateIdentityMetadataRequest that = (UpdateIdentityMetadataRequest) o;
        return Objects.equal(identityId, that.identityId) &&
                Objects.equal(identityIdToUpdate, that.identityIdToUpdate) &&
                Objects.equal(version, that.version) &&
                Objects.equal(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, identityIdToUpdate, version, metadata);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("identityId", identityId)
                .add("identityIdToUpdate", identityIdToUpdate)
                .add("version", version)
                .add("metadata", metadata)
                .toString();
    }

    public static UpdateIdentityMetadataRequestBuilder builder(String requestorId) {
        return new UpdateIdentityMetadataRequestBuilder(requestorId);
    }

    public static final class UpdateIdentityMetadataRequestBuilder {
        private final String identityId;

        private String identityIdToUpdate;

        private Long version;

        private Map<String, String> metadata;

        private UpdateIdentityMetadataRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public UpdateIdentityMetadataRequestBuilder withIdentityIdToUpdate(String identityIdToUpdate) {
            this.identityIdToUpdate = identityIdToUpdate;
            return this;
        }

        public UpdateIdentityMetadataRequestBuilder withVersion(long version) {
            this.version = version;
            return this;
        }

        public UpdateIdentityMetadataRequestBuilder withMetadata(Map<String, String> metadata) {
            this.metadata = metadata;
            return this;
        }

        public UpdateIdentityMetadataRequest build() {
            return new UpdateIdentityMetadataRequest(
                    identityId, identityIdToUpdate, version, metadata);
        }
    }
}
