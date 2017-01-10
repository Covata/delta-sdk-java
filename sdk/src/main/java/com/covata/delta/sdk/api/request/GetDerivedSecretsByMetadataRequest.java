package com.covata.delta.sdk.api.request;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import com.google.common.base.Objects;

public final class GetDerivedSecretsByMetadataRequest {

    private final String identityId;

    private final String rsaKeyOwnerId;

    private final Map<String, String> metadata;

    private final int page;

    private final int pageSize;

    public GetDerivedSecretsByMetadataRequest(String identityId, String rsaKeyOwnerId,
                                              Map<String, String> metadata,
                                              int page, int pageSize) {
        checkArgument(!Strings.isNullOrEmpty(identityId), "requesting identity id must be specified");
        checkArgument(!Strings.isNullOrEmpty(rsaKeyOwnerId), "requesting RSA key owner id must be specified");
        checkArgument(metadata != null, "metadata must be specified");

        this.identityId = identityId;
        this.rsaKeyOwnerId = rsaKeyOwnerId;
        this.metadata = ImmutableMap.copyOf(metadata);
        this.page = page;
        this.pageSize = pageSize;
    }

    public String getIdentityId() {
        return identityId;
    }

    public String getRsaKeyOwnerId() {
        return rsaKeyOwnerId;
    }

    public Optional<Map<String, String>> getMetadata() {
        return Optional.ofNullable(metadata);
    }

    public Optional<Integer> getPage() {
        return Optional.ofNullable(page);
    }

    public Optional<Integer> getPageSize() {
        return Optional.ofNullable(pageSize);
    }

    public static GetDerivedSecretsByMetadataRequestBuilder builder(String requestorId) {
        return new GetDerivedSecretsByMetadataRequestBuilder(requestorId);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(identityId, rsaKeyOwnerId, metadata, page, pageSize);
    }

    @Override
    public boolean equals(Object object) {
        if (object instanceof GetDerivedSecretsByMetadataRequest) {
            GetDerivedSecretsByMetadataRequest that = (GetDerivedSecretsByMetadataRequest) object;
            return Objects.equal(this.identityId, that.identityId)
                    && Objects.equal(this.rsaKeyOwnerId, that.rsaKeyOwnerId)
                    && Objects.equal(this.metadata, that.metadata)
                    && Objects.equal(this.page, that.page)
                    && Objects.equal(this.pageSize, that.pageSize);
        }
        return false;
    }

    public static final class GetDerivedSecretsByMetadataRequestBuilder {
        private final String identityId;

        private String rsaKeyOwnerId;

        private Map<String, String> metadata;

        private int page;

        private int pageSize;

        private GetDerivedSecretsByMetadataRequestBuilder(String identityId) {
            this.identityId = identityId;
        }

        public GetDerivedSecretsByMetadataRequestBuilder withRsaKeyOwnerId(String rsaKeyOwnerId) {
            this.rsaKeyOwnerId = rsaKeyOwnerId;
            return this;
        }

        public GetDerivedSecretsByMetadataRequestBuilder withMetadata(Map<String, String> metadata) {
            this.metadata = metadata;
            return this;
        }

        public GetDerivedSecretsByMetadataRequestBuilder withPage(int page) {
            this.page = page;
            return this;
        }

        public GetDerivedSecretsByMetadataRequestBuilder withPageSize(int pageSize) {
            this.pageSize = pageSize;
            return this;
        }

        public GetDerivedSecretsByMetadataRequest build() {
            return new GetDerivedSecretsByMetadataRequest(identityId, rsaKeyOwnerId, metadata, page, pageSize);
        }
    }

}
