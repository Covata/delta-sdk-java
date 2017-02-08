/*
 * Copyright 2016 Covata Limited or its affiliates
 *
 *
 *  Information contained within this file cannot be copied,
 *  distributed and/or practised without the written consent of
 *  Covata Limited or its affiliates.
 */

package com.covata.delta.sdk.api.util;

import com.covata.delta.sdk.api.request.CreateIdentityRequest;
import com.covata.delta.sdk.api.response.CreateIdentityResponse;
import com.covata.delta.sdk.crypto.DeltaKeyStore;
import com.covata.delta.sdk.exception.DeltaClientException;
import com.covata.delta.sdk.model.DeltaIdentity;
import com.covata.delta.sdk.test.util.SharedTestKeys;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HttpHeaders;
import com.google.common.net.MediaType;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import okhttp3.Request;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.Header;
import retrofit2.http.POST;
import retrofit2.http.Query;
import retrofit2.http.QueryMap;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AuthorizationUtilTest {

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private static final String CVT_SIGNING_ALGORITHM = "CVT1-RSA4096-SHA256";

    private static final String IDENTITY_ID = "9dsf0-asd098-s9d8fa0sdf-9sdf";

    private static final String SIGNING_PUBLIC_KEY = "E021472BCF554198752798A956DCB5065126D578CCCF632A6BB2BA1EEF7EE685";

    private static final String ENCRYPTION_PUBLIC_KEY = "220418D56A32B5B747EF301E57FA1466C229F03B1B11CC5B7900A996ACF360E8";

    private static final String REQUEST_DATE = "20150830T123600Z";

    private static final String CANONICAL_HEADERS = "content-type:application/json; charset=utf-8\n" +
            " cvt-date:20150830T123600Z\n" +
            " cvt-identity-id:" + IDENTITY_ID + "\n" +
            " host:example.server";

    private static final String SIGNED_HEADERS = "content-type;cvt-date;cvt-identity-id;host";

    private static final String HASHED_PAYLOAD = "daadd72c2e2f5b63ad67e2131a598e4a6edcd75d6bc70c36e7e3f3ec5de95417";

    private static final String CANONICAL_REQUEST = "POST\n" +
            "/clients/\n" +
            "sampleQueryParamName=sampleQueryParamValue\n" +
            CANONICAL_HEADERS + "\n" +
            SIGNED_HEADERS + "\n" +
            HASHED_PAYLOAD;

    private static final String HASHED_CANONICAL_REQUEST = "e9ff4cb9421521819aa1904740877e394436e68f39450556d4556eb144ec5924";

    private static final String STRING_TO_SIGN = CVT_SIGNING_ALGORITHM + "\n" +
            REQUEST_DATE + "\n" +
            HASHED_CANONICAL_REQUEST;

    private static final String MOCK_HOST = "https://example.server/master/";

    private static final String CVT_DATE = "Cvt-Date";

    private static final String CVT_IDENTITY_ID = "Cvt-Identity-Id";

    private MockDeltaApi mockDeltaApi;

    private Request request;

    private interface MockDeltaApi {
        @POST("clients")
        Call<CreateIdentityResponse> register(@Header(CVT_DATE) String date,
                                              @Header(HttpHeaders.HOST) String host,
                                              @Header(CVT_IDENTITY_ID) String identityId,
                                              @Query("sampleQueryParamName") String query,
                                              @Body CreateIdentityRequest request);

        @GET("clients")
        Call<List<DeltaIdentity>> findClients(@QueryMap Map<String, String> query);
    }

    @Before
    public void setup() throws IOException {
        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.start();

        JacksonConverterFactory converterFactory = JacksonConverterFactory.create(new ObjectMapper());

        mockDeltaApi = new Retrofit.Builder()
                .baseUrl(mockWebServer.url(MOCK_HOST).toString())
                .addConverterFactory(converterFactory)
                .build().create(MockDeltaApi.class);

        CreateIdentityRequest createIdentityRequest =
                new CreateIdentityRequest(SIGNING_PUBLIC_KEY, ENCRYPTION_PUBLIC_KEY, null, null);
        Call<CreateIdentityResponse> call
                = mockDeltaApi.register(REQUEST_DATE,
                "example.server", IDENTITY_ID, "sampleQueryParamValue", createIdentityRequest);
        request = call.request()
                .newBuilder() // fix as okhttp removes content-type header
                .addHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                .build();
    }

    @Test
    public void shouldReturnCorrectCanonicalHeaders() {
        String canonicalHeaders = AuthorizationUtil.getCanonicalHeaders(request);
        assertEquals(CANONICAL_HEADERS, canonicalHeaders);
    }

    @Test
    public void shouldReturnCorrectSignedHeaders() {
        String canonicalHeaders = AuthorizationUtil.getSignedHeaders(request);
        assertEquals(SIGNED_HEADERS, canonicalHeaders);
    }

    @Test
    public void shouldConvertSequentialSpacesToSingleSpace() {
        Request r = request.newBuilder().addHeader("spaces", "  a   b  c   ").build();

        String canonicalHeaders = AuthorizationUtil.getCanonicalHeaders(r);
        String expected = "content-type:application/json; charset=utf-8\n" +
                " cvt-date:20150830T123600Z\n" +
                " cvt-identity-id:" + IDENTITY_ID + "\n" +
                " host:example.server\n" +
                " spaces:a b c";
        assertEquals(expected, canonicalHeaders);
    }

    @Test
    public void shouldOrderAndEncodeQueryStringCorrectly() throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("name", "Natalie");
        query.put("favouriteColour", "black and red");
        query.put("email", "natalie@delta.com");

        Call<List<DeltaIdentity>> call = mockDeltaApi.findClients(query);
        request = call.request();

        String queryString = AuthorizationUtil.getCanonicalQueryString(request);
        assertEquals("email=natalie%40delta.com&favouriteColour=black%20and%20red&name=Natalie", queryString);
    }

    @Test
    public void shouldReturnCorrectStringToSign() {
        String hashedCanonicalRequest = DigestUtils.sha256Hex(CANONICAL_REQUEST);

        String stringToSign = AuthorizationUtil.getStringToSign(REQUEST_DATE,
                hashedCanonicalRequest);

        assertEquals(STRING_TO_SIGN, stringToSign);
    }

    @Test
    public void shouldReturnCorrectHashedPayload() throws Exception {
        String hashedPayload = AuthorizationUtil.getHashedPayload(request);
        assertEquals(HASHED_PAYLOAD, hashedPayload);
    }


    @Test
    public void shouldReturnCorrectCanonicalRequest() throws Exception {
        String canonicalRequest = AuthorizationUtil.getCanonicalRequest(request);
        assertEquals(CANONICAL_REQUEST, canonicalRequest);
    }

    @Test
    public void shouldReturnCorrectHashedCanonicalRequest() throws Exception {
        String hashedCanonicalRequest =
                DigestUtils.sha256Hex(AuthorizationUtil.getCanonicalRequest(request));
        assertEquals(HASHED_CANONICAL_REQUEST, hashedCanonicalRequest);
    }

    @Test
    public void shouldReturnCorrectAuthHeader() throws Exception {
        String expectedAuthPrefix = "CVT1-RSA4096-SHA256 Identity=9dsf0-asd098-s9d8fa0sdf-9sdf, " +
                "SignedHeaders=content-type;cvt-date;cvt-identity-id;host, Signature=";
        KeyPair keyPair = SharedTestKeys.SIGNING_KEY_PAIR;

        DeltaKeyStore mockKeyStore = Mockito.mock(DeltaKeyStore.class);
        Mockito.when(mockKeyStore.getPrivateSigningKey(IDENTITY_ID)).thenReturn(keyPair.getPrivate());

        String authHeader = AuthorizationUtil.getAuthHeader(request, IDENTITY_ID, mockKeyStore);

        String signature = authHeader.substring(authHeader.indexOf("Signature=") + 10);

        assertEquals(expectedAuthPrefix,
                authHeader.substring(0, authHeader.indexOf("Signature=") + 10));
        assertTrue(verify(STRING_TO_SIGN.getBytes(Charset.forName("UTF-8")),
                BaseEncoding.base64().decode(signature), keyPair.getPublic()));
    }

    private boolean verify(byte[] expected, byte[] signature, PublicKey publicKey)
            throws DeltaClientException {
        try {
            Signature signer = Signature.getInstance("SHA256withRSAandMGF1");
            signer.initVerify(publicKey);
            signer.update(expected);
            return signer.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new DeltaClientException(e);
        }
    }
}
