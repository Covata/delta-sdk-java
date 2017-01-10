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

import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import com.google.common.base.Objects;

public final class GetDerivedSecretsRequest {

    private final String identityId;

    private final String baseSecretId;

    private final int page;

    private final int pageSize;

    public GetDerivedSecretsRequest(String identityId, String baseSecretId,
                                    int page, int pageSize) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(baseSecretId), "base secret id must be specified");
        this.identityId = identityId;
        this.baseSecretId = baseSecretId;
        this.page = page;
        this.pageSize = pageSize;
    }

    public String getIdentityId() {
        return identityId;
    }

    public String getBaseSecretId() {
        return baseSecretId;
    }

    public Optional<Integer> getPage() {
        return Optional.ofNullable(page);
    }

    public Optional<Integer> getPageSize() {
        return Optional.ofNullable(pageSize);
    }

    public static GetDerivedSecretsRequestBuilder builder(String requestorId) {
        return new GetDerivedSecretsRequestBuilder(requestorId);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, baseSecretId, page, pageSize);
    }

    @Override
    public boolean equals(Object object) {
        if (object instanceof GetDerivedSecretsRequest) {
            GetDerivedSecretsRequest that = (GetDerivedSecretsRequest) object;
            return Objects.equal(this.identityId, that.identityId)
                    && Objects.equal(this.baseSecretId, that.baseSecretId)
                    && Objects.equal(this.page, that.page)
                    && Objects.equal(this.pageSize, that.pageSize);
        }
        return false;
    }

    public static final class GetDerivedSecretsRequestBuilder {
        private final String identityId;

        private String secretId;

        private int page;

        private int pageSize;

        private GetDerivedSecretsRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public GetDerivedSecretsRequestBuilder withSecretId(String secretId) {
            this.secretId = secretId;
            return this;
        }

        public GetDerivedSecretsRequestBuilder withPage(int page) {
            this.page = page;
            return this;
        }

        public GetDerivedSecretsRequestBuilder withPageSize(int pageSize) {
            this.pageSize = pageSize;
            return this;
        }

        public GetDerivedSecretsRequest build() {
            return new GetDerivedSecretsRequest(identityId, secretId, page, pageSize);
        }
    }
}
