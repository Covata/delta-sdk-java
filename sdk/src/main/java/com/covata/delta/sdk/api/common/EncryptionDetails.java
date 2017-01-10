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

package com.covata.delta.sdk.api.common;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;

@JsonPropertyOrder(alphabetic = true)
public class EncryptionDetails {

    private final String symmetricKey;

    private final String initialisationVector;

    @JsonCreator
    public EncryptionDetails(@JsonProperty("symmetricKey") String symmetricKey,
                             @JsonProperty("initialisationVector") String initialisationVector) {
        this.symmetricKey = symmetricKey;
        this.initialisationVector = initialisationVector;
    }

    public String getSymmetricKey() {
        return symmetricKey;
    }

    public String getInitialisationVector() {
        return initialisationVector;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        EncryptionDetails that = (EncryptionDetails) o;
        return Objects.equal(symmetricKey, that.symmetricKey) &&
                Objects.equal(initialisationVector, that.initialisationVector);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(symmetricKey, initialisationVector);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("symmetricKey", symmetricKey)
                .add("initialisationVector", initialisationVector)
                .toString();
    }
}
