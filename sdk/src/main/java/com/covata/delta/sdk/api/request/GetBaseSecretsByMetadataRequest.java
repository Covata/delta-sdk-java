package com.covata.delta.sdk.api.request;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import com.google.common.base.Objects;

public final class GetBaseSecretsByMetadataRequest {

    private final String identityId;

    private final String createdBy;

    private final Map<String, String> metadata;

    private final int page;

    private final int pageSize;

    public Optional<Map<String, String>> getMetadata() {
        return Optional.ofNullable(metadata);
    }

    public GetBaseSecretsByMetadataRequest(String identityId, String createdBy, Map<String, String> metadata,
                                           int page, int pageSize) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "the requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(createdBy), "requesting creator id must be specified");
        this.identityId = identityId;
        this.createdBy = createdBy;
        this.metadata = metadata != null ? ImmutableMap.copyOf(metadata) : null;
        this.page = page;
        this.pageSize = pageSize;
    }

    public String getIdentityId() {
        return identityId;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public Optional<Integer> getPage() {
        return Optional.ofNullable(page);
    }

    public Optional<Integer> getPageSize() {
        return Optional.ofNullable(pageSize);
    }

    public static GetBaseSecretsByMetadataRequestBuilder builder(String requestorId) {
        return new GetBaseSecretsByMetadataRequestBuilder(requestorId);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, createdBy, metadata, page, pageSize);
    }

    @Override
    public boolean equals(Object object) {
        if (object instanceof GetBaseSecretsByMetadataRequest) {
            GetBaseSecretsByMetadataRequest that = (GetBaseSecretsByMetadataRequest) object;
            return Objects.equal(this.identityId, that.identityId)
                    && Objects.equal(this.createdBy, that.createdBy)
                    && Objects.equal(this.metadata, that.metadata)
                    && Objects.equal(this.page, that.page)
                    && Objects.equal(this.pageSize, that.pageSize);
        }
        return false;
    }

    public static final class GetBaseSecretsByMetadataRequestBuilder {
        private final String identityId;

        private String createdBy;

        private Map<String, String> metadata;

        private int page;

        private int pageSize;

        private GetBaseSecretsByMetadataRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public GetBaseSecretsByMetadataRequestBuilder withCreatedBy(String createdBy) {
            this.createdBy = createdBy;
            return this;
        }

        public GetBaseSecretsByMetadataRequestBuilder withMetadata(Map<String, String> metadata) {
            this.metadata = metadata;
            return this;
        }

        public GetBaseSecretsByMetadataRequestBuilder withPage(int page) {
            this.page = page;
            return this;
        }

        public GetBaseSecretsByMetadataRequestBuilder withPageSize(int pageSize) {
            this.pageSize = pageSize;
            return this;
        }

        public GetBaseSecretsByMetadataRequest build() {
            return new GetBaseSecretsByMetadataRequest(identityId, createdBy, metadata, page, pageSize);
        }
    }

}
