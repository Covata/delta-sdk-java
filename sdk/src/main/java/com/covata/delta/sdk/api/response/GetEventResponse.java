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

import com.fasterxml.jackson.annotation.JsonProperty;

public class GetEventResponse {

    @JsonProperty
    private String id;

    @JsonProperty
    private String sourceIp;

    @JsonProperty
    private String timestamp;

    @JsonProperty
    private String type;

    @JsonProperty
    private String host;

    @JsonProperty
    EventDetails eventDetails;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getType() {
        return type;
    }

    public void setType(String eventName) {
        this.type = eventName;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public EventDetails getEventDetails() {
        return eventDetails;
    }

    public void setEventDetails(EventDetails eventDetails) {
        this.eventDetails = eventDetails;
    }


    public static class EventDetails {

        @JsonProperty
        private String secretId;

        @JsonProperty
        private String baseSecretId;

        @JsonProperty
        private String requesterId;

        @JsonProperty
        private String secretOwnerId;

        @JsonProperty
        private String rsaKeyOwnerId;

        public String getSecretId() {
            return secretId;
        }

        public void setSecretId(String secretId) {
            this.secretId = secretId;
        }

        public String getBaseSecretId() {
            return baseSecretId;
        }

        public void setBaseSecretId(String baseSecretId) {
            this.baseSecretId = baseSecretId;
        }

        public String getRequesterId() {
            return requesterId;
        }

        public void setRequesterId(String secretId) {
            this.requesterId = secretId;
        }

        public String getSecretOwnerId() {
            return secretOwnerId;
        }

        public void setSecretOwnerId(String secretCreatorId) {
            this.secretOwnerId = secretCreatorId;
        }

        public String getRsaKeyOwnerId() {
            return rsaKeyOwnerId;
        }

        public void setRsaKeyOwnerId(String rsaKeyOwnerId) {
            this.rsaKeyOwnerId = rsaKeyOwnerId;
        }
    }
}
