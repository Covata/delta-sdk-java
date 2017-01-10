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

public final class GetEventsRequest {

    private final String identityId;

    private final String secretId;

    private final String rsaKeyOwner;

    public GetEventsRequest(String identityId, String secretId, String rsaKeyOwner) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        this.identityId = identityId;
        this.secretId = secretId;
        this.rsaKeyOwner = rsaKeyOwner;
    }

    public String getIdentityId() {
        return identityId;
    }

    public Optional<String> getSecretId() {
        return Optional.ofNullable(secretId);
    }

    public Optional<String> getRsaKeyOwner() {
        return Optional.ofNullable(rsaKeyOwner);
    }

    public static GetEventsRequestBuilder builder(String requestorId) {
        return new GetEventsRequestBuilder(requestorId);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, secretId, rsaKeyOwner);
    }

    @Override
    public boolean equals(Object object) {
        if (object instanceof GetEventsRequest) {
            GetEventsRequest that = (GetEventsRequest) object;
            return Objects.equal(this.identityId, that.identityId)
                    && Objects.equal(this.secretId, that.secretId)
                    && Objects.equal(this.rsaKeyOwner, that.rsaKeyOwner);
        }
        return false;
    }

    public static final class GetEventsRequestBuilder {
        private final String identityId;

        private String secretId;

        private String rsaKeyOwner;

        private GetEventsRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public GetEventsRequestBuilder withSecretId(String secretId) {
            this.secretId = secretId;
            return this;
        }

        public GetEventsRequestBuilder withRsaKeyOwner(String rsaKeyOwner) {
            this.rsaKeyOwner = rsaKeyOwner;
            return this;
        }

        public GetEventsRequest build() {
            return new GetEventsRequest(identityId, secretId, rsaKeyOwner);
        }
    }
}
