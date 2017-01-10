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

import static com.google.common.base.Preconditions.checkArgument;

public final class SecretRequest {
    
    private final String identityId;

    private final String secretId;

    public SecretRequest(String identityId, String secretId) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(secretId), "secret id must be specified");
        this.identityId = identityId;
        this.secretId = secretId;
    }

    public String getIdentityId() {
        return identityId;
    }

    public String getSecretId() {
        return secretId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SecretRequest request = (SecretRequest) o;
        return Objects.equal(identityId, request.identityId) &&
                Objects.equal(secretId, request.secretId);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, secretId);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("identityId", identityId)
                .add("secretId", secretId)
                .toString();
    }

    public static SecretRequestBuilder builder(String requestorId) {
        return new SecretRequestBuilder(requestorId);
    }

    public static final class SecretRequestBuilder {
        private final String identityId;

        private String secretId;

        private SecretRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public SecretRequestBuilder withSecretId(String secretId) {
            this.secretId = secretId;
            return this;
        }

        public SecretRequest build() {
            return new SecretRequest(identityId, secretId);
        }
    }
}
