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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import com.google.common.base.Objects;

public final class GetIdentitiesByMetadataRequest {

    private final String identityId;

    private final Map<String, String> metadata;

    private final int page;

    private final int pageSize;

    public Map<String, String> getMetadata() {
        return metadata;
    }

    public GetIdentitiesByMetadataRequest(String identityId,
                                          Map<String, String> metadata,
                                          int page,
                                          int pageSize) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(metadata != null, "metadata must be specified");

        this.identityId = identityId;
        this.metadata = ImmutableMap.copyOf(metadata);
        this.page = page;
        this.pageSize = pageSize;
    }

    public String getIdentityId() {
        return identityId;
    }

    public Optional<Integer> getPage() {
        return Optional.ofNullable(page);
    }

    public Optional<Integer> getPageSize() {
        return Optional.ofNullable(pageSize);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, metadata, page, pageSize);
    }

    @Override
    public boolean equals(Object object) {
        if (object instanceof GetIdentitiesByMetadataRequest) {
            GetIdentitiesByMetadataRequest that = (GetIdentitiesByMetadataRequest) object;
            return Objects.equal(this.identityId, that.identityId)
                    && Objects.equal(this.metadata, that.metadata)
                    && Objects.equal(this.page, that.page)
                    && Objects.equal(this.pageSize, that.pageSize);
        }
        return false;
    }

    public static GetIdentitiesByMetadataRequestBuilder builder(String requestorId) {
        return new GetIdentitiesByMetadataRequestBuilder(requestorId);
    }

    public static final class GetIdentitiesByMetadataRequestBuilder {
        private final String identityId;

        private Map<String, String> metadata;

        private int page;

        private int pageSize;

        private GetIdentitiesByMetadataRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public GetIdentitiesByMetadataRequestBuilder withMetadata(Map<String, String> metadata) {
            this.metadata = metadata;
            return this;
        }

        public GetIdentitiesByMetadataRequestBuilder withPage(int page) {
            this.page = page;
            return this;
        }

        public GetIdentitiesByMetadataRequestBuilder withPageSize(int pageSize) {
            this.pageSize = pageSize;
            return this;
        }

        public GetIdentitiesByMetadataRequest build() {
            return new GetIdentitiesByMetadataRequest(
                    identityId, metadata, page, pageSize);
        }
    }
}
