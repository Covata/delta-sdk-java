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

package com.covata.delta.sdk.api.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GetIdentityResponse {

    private final String id;

    private final String encryptionPublicKey;

    private final Map<String, String> metadata;

    private final String externalId;

    private final Long version;

    @JsonCreator
    public GetIdentityResponse(@JsonProperty("id") String id,
                               @JsonProperty("cryptoPublicKey") String encryptionPublicKey,
                               @JsonProperty("metadata") Map<String, String> metadata,
                               @JsonProperty("externalId") String externalId,
                               @JsonProperty("version") Long version) {
        this.id = id;
        this.encryptionPublicKey = encryptionPublicKey;
        this.metadata = ImmutableMap.copyOf(metadata);
        this.externalId = externalId;
        this.version = version;
    }

    public String getId() {
        return id;
    }

    public String getEncryptionPublicKey() {
        return encryptionPublicKey;
    }

    public Map<String, String> getMetadata() {
        return metadata;
    }

    public String getExternalId() {
        return externalId;
    }

    public Long getVersion() {
        return version;
    }

}
