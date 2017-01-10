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

package com.covata.delta.sdk.api.interceptor;

import com.covata.delta.sdk.api.util.AuthorizationUtil;
import com.covata.delta.sdk.crypto.DeltaKeyStore;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.google.common.collect.Sets;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import static com.covata.delta.sdk.api.common.DeltaHeaders.CVT_DATE;
import static com.covata.delta.sdk.api.common.DeltaHeaders.CVT_IDENTITY_ID;
import static com.covata.delta.sdk.api.util.AuthorizationUtil.getAuthHeader;
import static com.covata.delta.sdk.util.DateTimeUtil.*;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;

/**
 * This interceptor generates and inserts an Authorization header into the
 * request based on the scheme configured in {@link AuthorizationUtil}. A
 * date header will also be added to the request.
 */
public class AuthorizationInterceptor implements Interceptor {

    private static final Set<String> EXCLUSIONS = Sets.newHashSet();

    static {
        EXCLUSIONS.add("POST identities");
    }

    private final DeltaKeyStore keyStore;

    public AuthorizationInterceptor(final DeltaKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public Response intercept(final Chain chain) throws IOException {
        Request request = chain.request();

        if (!requiresAuthorization(request)) {
            return chain.proceed(request);
        }

        try {
            String identityId = request.header(CVT_IDENTITY_ID);
            Request datedRequest = request.newBuilder()
                    .removeHeader(AUTHORIZATION)
                    .removeHeader(CVT_IDENTITY_ID)
                    .removeHeader(CVT_DATE)
                    .addHeader(CVT_DATE, getRequestDateTime())
                    .build();

            String authHeader = getAuthHeader(datedRequest, identityId, keyStore);

            return chain.proceed(datedRequest.newBuilder()
                    .addHeader(AUTHORIZATION, authHeader)
                    .build());

        } catch (DeltaClientException e) {
            throw new IOException(e);
        }
    }

    private boolean requiresAuthorization(Request request) {
        List<String> pathSegments = request.url().pathSegments();
        if (pathSegments.size() < 1) {
            return false;
        }
        String endpoint = pathSegments.get(pathSegments.size() - 1);
        return !(EXCLUSIONS.contains(
                String.format("%s %s", request.method(), endpoint)));
    }
}
