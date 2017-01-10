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

package com.covata.delta.sdk.model;

/**
 * An instance of this class encapsulates an <i>event</i> in Covata Delta. An
 * event is an audit entry representing an action undertaken by an
 * <i>identity</i> on a <i>secret</i>.
 */
public class DeltaEvent {

    private final String id;

    private final String sourceIp;

    private final String timestamp;

    private final String eventName;

    private final String host;

    private final EventDetails eventDetails;

    private DeltaEvent(final DeltaEventBuilder builder) {
        this.id = builder.id;
        this.sourceIp = builder.sourceIp;
        this.timestamp = builder.timestamp;
        this.eventName = builder.eventName;
        this.host = builder.host;
        this.eventDetails = new EventDetails(builder);
    }

    public String getId() {
        return id;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getEventName() {
        return eventName;
    }

    public String getHost() {
        return host;
    }

    public EventDetails getEventDetails() {
        return eventDetails;
    }

    public static DeltaEventBuilder builder() {
        return new DeltaEventBuilder();
    }

    public static class EventDetails {

        private final String baseSecretId;

        private final String secretId;

        private final String requesterId;

        private final String secretCreatorId;

        private final String rsaKeyOwnerId;

        private EventDetails(final DeltaEventBuilder builder) {
            this.baseSecretId = builder.baseSecretId;
            this.secretId = builder.secretId;
            this.requesterId = builder.requesterId;
            this.secretCreatorId = builder.secretCreatorId;
            this.rsaKeyOwnerId = builder.rsaKeyOwnerId;
        }

        public String getBaseSecretId() {
            return baseSecretId;
        }

        public String getSecretId() {
            return secretId;
        }

        public String getRequesterId() {
            return requesterId;
        }

        public String getSecretCreatorId() {
            return secretCreatorId;
        }

        public String getRsaKeyOwnerId() {
            return rsaKeyOwnerId;
        }

    }

    public static final class DeltaEventBuilder {

        private String id;

        private String sourceIp;

        private String timestamp;

        private String eventName;

        private String host;

        private String baseSecretId;

        private String secretId;

        private String requesterId;

        private String secretCreatorId;

        private String rsaKeyOwnerId;

        public DeltaEventBuilder withId(String id) {
            this.id = id;
            return this;
        }

        public DeltaEventBuilder withSourceIp(String sourceIp) {
            this.sourceIp = sourceIp;
            return this;
        }

        public DeltaEventBuilder withTimestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public DeltaEventBuilder withEventName(String eventName) {
            this.eventName = eventName;
            return this;
        }

        public DeltaEventBuilder withHost(String host) {
            this.host = host;
            return this;
        }

        public DeltaEventBuilder withBaseSecretId(String baseSecretId) {
            this.baseSecretId = baseSecretId;
            return this;
        }

        public DeltaEventBuilder withSecretId(String secretId) {
            this.secretId = secretId;
            return this;
        }

        public DeltaEventBuilder withRequesterId(String requesterId) {
            this.requesterId = requesterId;
            return this;
        }

        public DeltaEventBuilder withSecretCreatorId(String secretCreatorId) {
            this.secretCreatorId = secretCreatorId;
            return this;
        }

        public DeltaEventBuilder withRsaKeyOwnerId(String rsaKeyOwnerId) {
            this.rsaKeyOwnerId = rsaKeyOwnerId;
            return this;
        }

        public DeltaEvent build() {
            return new DeltaEvent(this);
        }

    }

}
