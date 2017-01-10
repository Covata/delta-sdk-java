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
import com.covata.delta.sdk.api.request.CreateSecretRequest;
import com.covata.delta.sdk.api.request.ShareSecretRequest;
import com.covata.delta.sdk.api.response.CreateIdentityResponse;
import com.covata.delta.sdk.api.response.CreateSecretResponse;
import com.covata.delta.sdk.api.response.ShareSecretResponse;
import com.covata.delta.sdk.model.DeltaIdentity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import okhttp3.Request;
import org.junit.Before;
import org.junit.Test;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.QueryMap;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class AuthorizationUtilPayloadTest {

    private static final String MOCK_HOST = "https://example.server/master/";

    private static final String ENCRYPTION_PUBLIC_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtM6zFibfEkR3ybHXey43WLjYeO9CCFXCOJSrJUkE4PAOlsqhjmVj9KI8xoodXFXFrETOChTaXlSFkBcrIJO4AsyTtjsxpsN0zqzdn5oII+01LHIwntsV5+lR9cSwail+cNyi6vvMplDGJK3jg+pfyc5EyAASGNaGeq7yMR/gQ5SipRgETRfNujSt/40lsxrH97yXB+2mDw2q/rDpy6J0VZCsai3cgFTrEJPq/FIP9Dt5hsVwmd4ThGKyabQrjaxgXsjwVZ+eA0oMTPfgaabWn5DpFZLe5qCL0DfBvF1Dkb9i+af8gkSY5ptcrqDWvwfpyp5nG1bco50XhagWfzF0gWOa8Jkq3/7MCWob1DbL1M3YBR6JVpaaI8p0FylHuSv5fAxweDQMsQC9EmFNZTbd/Cb7TJ7tCZIwRHfJxxRYc7bddmRRNL2yLhl+94M2tSbsTq6fDkl2ihzFveEjbAyHbhfUedmtefEF4DY4kgAMmFGDu4mYSv9LHKUzipMZrOCUS1Sy5SQPJwFjZ4xRHJOjflt8AeP5ycwwEwsyhKboJPzeKSZyNJSeqAZOt7+rb4dqm7Qi4FkS+g7yHKHu/dCP9HnwH55e4rFXCO6jsQW2Z7fsMojqUIBOLdOvDvWQJGKRMOOZs/9XdECeV7nnP3lQ6yPV3G2CyMKZM9CEPRFZ8GkCAwEAAQ==";

    private static final String SIGNING_PUBLIC_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1sIc8mG/ekGQbkCdpNtv/9JDRNJ3wls6nyQXcR4vM9iPqqNV8ZlG5GcyyYVy0DMGsT+t0j9jyFxYsMDtE4dT/p4Jy+HX4hXH3k5nWjaawuc9A9XHCnDQIAS+Lunszf6erZ27Nb8fLbAYO0WMXz+tFtRjjkeMp/SNWYbHLIKtd/Odos3ZvWfqDz1RLFWWrfmVzS9/4d8upBcXakGiByQO2RbaU0xBXtMbC6xl2FJCY99VHBfPZRe0ZObdYhDputdJACgyw/Wa5rIc4ZlVxcvneQ1RWg32W274iiKW7YMcx50D1wWXEkmZ8x3MQrF73/twXX+yZodVsvHBuP3d38NjKa8IFATzEiVudUU6mt9iZv13r0kOX8C9rM53UDfQthAjEkYdUpSoNfk6o/0N+6avQErDvnn/uOYlZrGHtzDDPbmYsVt53Y5exBH0HD+Fg9z7IXOvp8l2ST7n61AmRhn0le6f+PJ5BJoj9JieuczTwWzidhMPFL66ypdCGpA0xxQzehvDZ6BOcfw8MrA572w58A+CePzW2X9EUIFpAI41K7y8temTiKg1AQe4L/Bo/+7v+owbSDXedHEqiiQ87tRe6kRGQ45aMYe4OpPkq4S2+5mblbqdT3ZD1wwN0C48dGhmRrulgFFB6Zm+y+sHEhff72ynGBWftYyGyoNB6+UYJg8CAwEAAQ==";

    private static final String EXTERNAL_ID = "Natalie123";

    private static final Map<String, String> METADATA = new HashMap<>();

    static {
        METADATA.put("email", "natalie@delta.com");
        METADATA.put("name", "Natalie");
    }

    private static final String CONTENT = "9Y4+IUE/FGIdhZbWvOkepVnRkgWYbHS4bDMv80lYSLaJRg==";

    private static final String INITIALISATION_VECTOR = "CQrCJQuzZ9skJ/3m6fu54Q==";

    private static final String SYMMETRIC_KEY = "BDiktuPujkf1lo7dfrqDQs/eQTPShgEt/WyIghWKqYEIqm23T7y07p/37J4jwKvCszoqlt59U8zz1ECEHYrkkU4swp82LIgkZFJGHMVRWUFPX8/jF8ghdZdq0EBF1tSTt/rezvr8CrDwahTZmSv/3ANyfMDXYf6DIo46JvsidIhPPRZGlfQQLrjpCbI7f8/ZxEj1pXUDy6T1QkYariNsOE5YLr7lxSum5Ag5UQouEvT5qbzUJJHke3nesAZsAHuF4Hg6NJ4V7ulN067XeKjwYOSHBe7QzRJMLGAn7NYbW/nTve0T5tM8x8SrlnMu4NtuqZaS0/YOgNYlIRlfVP5OoGEIamOfSlEv7YJUmLlrb6osqAxHjl/g5OtKroZA+HY9egmKc9Ds0CDonS1goJndrhF0tLtxfF74Eh6LKSlyTSDGQYEUsGQAce8fQhzN+wRaMhxYIAEgqz8kswi2QpsOHC2XcB88IudnvdfuysWmsMyNKxk1HOMuBYaSqN4taEdn2uUFttjocgyauqSFSAmILYY5W1aaZAhdGeyQbgERgC5q7N0OPzuwi6R1Aa4Jdh5lHQXHQAS9SzIFcTLSnMJbr7CS43Y+pXWiHBEFQIKDAYb2+8JMa9Jua/rCkdBKb2sLUZQTAa1H0ItBZEB+wfX6Rnad+qNWLgf1kcOEs6w6c/4=";

    private MockDeltaApi mockDeltaApi;

    private interface MockDeltaApi {
        @POST("identities")
        Call<CreateIdentityResponse> createIdentity(@Body CreateIdentityRequest request);

        @POST("secrets")
        Call<CreateSecretResponse> createSecret(@Body CreateSecretRequest request);

        @POST("secrets")
        Call<ShareSecretResponse> shareSecret(@Body ShareSecretRequest request);

        @GET("clients")
        Call<List<DeltaIdentity>> findClients(@QueryMap Map<String, String> query);
    }

    @Before
    public void setup() throws IOException {
        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.start();

        JacksonConverterFactory converterFactory = JacksonConverterFactory.create(
                new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true));

        mockDeltaApi = new Retrofit.Builder()
                .baseUrl(mockWebServer.url(MOCK_HOST).toString())
                .addConverterFactory(converterFactory)
                .build().create(MockDeltaApi.class);
    }

    @Test
    public void shouldReturnCorrectPayloadHashForCreateIdentity() throws Exception {
        String expected = "66a48989021c577ec3bf964dc96fc306c748bde768bcfa404710ab08992937bf";
        Call<CreateIdentityResponse> call = mockDeltaApi.createIdentity(
                CreateIdentityRequest
                        .builder(SIGNING_PUBLIC_KEY, ENCRYPTION_PUBLIC_KEY)
                        .withMetadata(METADATA)
                        .withExternalId(EXTERNAL_ID)
                        .build());
        Request request = call.request();
        String result = AuthorizationUtil.getHashedPayload(request);
        assertEquals(expected, result);
    }

    @Test
    public void shouldReturnCorrectPayloadHashForCreateSecret() throws Exception {
        String expected = "dafb22e6b3e63271a961b30e57fda97f5309d7268fe0f25167b14852a788b4b8";
        Call<CreateSecretResponse> call = mockDeltaApi.createSecret(
                CreateSecretRequest.builder("123")
                        .withContent(CONTENT)
                        .withEncryptionDetails(SYMMETRIC_KEY, INITIALISATION_VECTOR)
                        .build());
        Request request = call.request();
        String result = AuthorizationUtil.getHashedPayload(request);
        assertEquals(expected, result);
    }

    @Test
    public void shouldReturnCorrectEmptyPayload() throws Exception {
        String expected = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
        Map<String, String> query = new HashMap<>();
        Call<List<DeltaIdentity>> call = mockDeltaApi.findClients(query);
        Request request = call.request();
        String result = AuthorizationUtil.getHashedPayload(request);
        assertEquals(expected, result);
    }
}
