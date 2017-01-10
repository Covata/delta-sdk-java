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

public class GetIdentityRequest {

    private final String identityId;

    private final String identityIdToRetrieve;

    public GetIdentityRequest(String identityId, String identityIdToRetrieve) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(identityIdToRetrieve), "identity id to retrieve must be specified");
        this.identityId = identityId;
        this.identityIdToRetrieve = identityIdToRetrieve;
    }

    public String getIdentityId() {
        return identityId;
    }

    public String getIdentityIdToRetrieve() {
        return identityIdToRetrieve;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        GetIdentityRequest that = (GetIdentityRequest) o;
        return Objects.equal(identityId, that.identityId) &&
                Objects.equal(identityIdToRetrieve, that.identityIdToRetrieve);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, identityIdToRetrieve);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("identityId", identityId)
                .add("identityIdToRetrieve", identityIdToRetrieve)
                .toString();
    }

    public static GetIdentityRequestBuilder builder(String requestorId) {
        return new GetIdentityRequestBuilder(requestorId);
    }

    public static final class GetIdentityRequestBuilder {
        private final String identityId;

        private String identityIdToRetrieve;

        private GetIdentityRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public GetIdentityRequestBuilder withIdentityIdToRetrieve(String identityIdToRetrieve) {
            this.identityIdToRetrieve = identityIdToRetrieve;
            return this;
        }

        public GetIdentityRequest build() {
            return new GetIdentityRequest(identityId, identityIdToRetrieve);
        }
    }
}
