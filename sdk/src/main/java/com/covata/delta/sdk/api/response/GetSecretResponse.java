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

import com.covata.delta.sdk.api.common.EncryptionDetails;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GetSecretResponse {

    private final String id;

    private final String createdBy;

    private final String rsaKeyOwner;

    private final String created;

    private final String modified;

    private final EncryptionDetails encryptionDetails;

    private final boolean derived;

    private final String href;

    @JsonCreator
    public GetSecretResponse(@JsonProperty("id") String id,
                             @JsonProperty("createdBy") String createdBy,
                             @JsonProperty("rsaKeyOwner") String rsaKeyOwner,
                             @JsonProperty("created") String created,
                             @JsonProperty("modified") String modified,
                             @JsonProperty("encryptionDetails") EncryptionDetails encryptionDetails,
                             @JsonProperty("derived") boolean derived,
                             @JsonProperty("href") String href) {
        this.id = id;
        this.createdBy = createdBy;
        this.rsaKeyOwner = rsaKeyOwner;
        this.created = created;
        this.modified = modified;
        this.encryptionDetails = encryptionDetails;
        this.derived = derived;
        this.href = href;
    }

    public String getHref() {
        return href;
    }

    public String getId() {
        return id;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public String getRsaKeyOwner() {
        return rsaKeyOwner;
    }

    public String getCreated() {
        return created;
    }

    public String getModified() {
        return modified;
    }

    public EncryptionDetails getEncryptionDetails() {
        return encryptionDetails;
    }

    public boolean isDerived() {
        return derived;
    }

}
