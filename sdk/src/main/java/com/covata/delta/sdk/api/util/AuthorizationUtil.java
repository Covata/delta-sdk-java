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
package com.covata.delta.sdk.api.util;

import com.covata.delta.sdk.crypto.DeltaKeyStore;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.google.common.io.BaseEncoding;
import okhttp3.Request;
import okio.Buffer;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import static com.covata.delta.sdk.api.common.DeltaHeaders.CVT_DATE;
import static org.apache.commons.codec.digest.DigestUtils.sha256Hex;

/**
 * Utility methods for request signing using CVT1-RSA4096-SHA256.
 */
public class AuthorizationUtil {
    private static final Charset STRING_ENCODING_CHARSET = Charset.forName("UTF-8");

    private static final String CVT_SCHEME = "CVT1-RSA4096-SHA256";

    private static final String SIGNING_ALGORITHM = "SHA256withRSAandMGF1";

    static String getCanonicalRequest(Request request)
            throws DeltaClientException {
        try {
            return new StringJoiner("\n")
                    .add(request.method())
                    .add(getCanonicalUri(request))
                    .add(getCanonicalQueryString(request))
                    .add(getCanonicalHeaders(request))
                    .add(getSignedHeaders(request))
                    .add(getHashedPayload(request))
                    .toString();
        } catch (IOException e) {
            throw new DeltaClientException(e);
        }
    }

    static String getCanonicalUri(Request request) {
        String path = request.url().encodedPath()
                .substring(request.url().encodedPath().indexOf('/', 1));
        return path.isEmpty() || path.charAt(path.length() - 1) != '/' ? path + '/' : path;
    }

    static String getCanonicalQueryString(Request request) {
        String s = request.url().queryParameterNames().stream()
                .sorted()
                .map(p -> {
                    try {
                        return String.format("%s=%s",
                                URLEncoder.encode(p, "UTF-8")
                                        .replace("+", "%20")
                                        .replaceAll("(?i)%7e", "~"),
                                URLEncoder.encode(request.url().queryParameter(p), "UTF-8")
                                        .replace("+", "%20")
                                        .replaceAll("(?i)%7e", "~"));
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException("Error encoding query String", e);
                    }
                })
                .collect(Collectors.joining("&"));
        return s;
    }

    static String getCanonicalHeaders(Request request) {
        return request.headers().names().stream()
                .map(String::toLowerCase)
                .sorted()
                .map(n -> String.format("%s:%s", n,
                        request.headers().get(n).trim().replaceAll("\\s+", " ")))
                .collect(Collectors.joining("\n "));
    }

    static String getSignedHeaders(Request request) {
        return request.headers().names().stream()
                .map(String::toLowerCase)
                .sorted()
                .collect(Collectors.joining(";"));
    }

    static String getHashedPayload(Request request) throws IOException {
        String payload = "{}";
        if (!request.method().equals("GET") && !request.method().equals("DELETE")) {
            final Request copy = request.newBuilder().build();
            final Buffer buffer = new Buffer();
            copy.body().writeTo(buffer);
            payload = buffer.readUtf8();
        }
        return sha256Hex(payload).toLowerCase();
    }

    static String getStringToSign(String date, String hashedCanonicalRequest) {
        return new StringJoiner("\n")
                .add(CVT_SCHEME)
                .add(date)
                .add(hashedCanonicalRequest)
                .toString();
    }

    static String sign(String stringToSign, PrivateKey privateKey)
            throws DeltaClientException {
        try {
            Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
            signer.initSign(privateKey);
            signer.update(stringToSign.getBytes(STRING_ENCODING_CHARSET));
            byte[] signatureBytes = signer.sign();
            return BaseEncoding.base64().encode(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new DeltaClientException(e);
        }
    }

    /**
     * Generate an authorization header for the <code>Request</code>.
     *
     * @param request the request to be signed
     * @param identityId the identityId whose signing key will sign the request
     * @param keyStore the keyStore to retrieve the signing key
     * @return the Authorization header
     * @throws DeltaClientException on exception generating the header
     */
    public static String getAuthHeader(Request request,
                                       String identityId,
                                       DeltaKeyStore keyStore)
            throws DeltaClientException {
        String hashedCanonicalRequest = sha256Hex(getCanonicalRequest(request));

        PrivateKey signingKey = keyStore.getPrivateSigningKey(identityId);

        String dateString = request.header(CVT_DATE);
        String stringToSign = getStringToSign(dateString, hashedCanonicalRequest);

        String signedHeaders = getSignedHeaders(request);
        String signature = sign(stringToSign, signingKey);

        return String.format("%s Identity=%s, SignedHeaders=%s, Signature=%s",
                CVT_SCHEME, identityId, signedHeaders, signature);
    }
}
