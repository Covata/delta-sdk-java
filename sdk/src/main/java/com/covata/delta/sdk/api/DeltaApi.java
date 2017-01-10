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

package com.covata.delta.sdk.api;

import com.covata.delta.sdk.api.request.CreateIdentityRequest;
import com.covata.delta.sdk.api.request.CreateSecretRequest;
import com.covata.delta.sdk.api.request.ShareSecretRequest;
import com.covata.delta.sdk.api.request.UpdateIdentityMetadataRequest;
import com.covata.delta.sdk.api.response.CreateIdentityResponse;
import com.covata.delta.sdk.api.response.CreateSecretResponse;
import com.covata.delta.sdk.api.response.GetEventResponse;
import com.covata.delta.sdk.api.response.GetIdentityResponse;
import com.covata.delta.sdk.api.response.GetSecretResponse;
import com.covata.delta.sdk.api.response.GetSecretsResponse;
import com.covata.delta.sdk.api.response.ShareSecretResponse;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.DELETE;
import retrofit2.http.GET;
import retrofit2.http.Header;
import retrofit2.http.POST;
import retrofit2.http.PUT;
import retrofit2.http.Path;
import retrofit2.http.Query;
import retrofit2.http.QueryMap;

import java.util.List;
import java.util.Map;

import static com.covata.delta.sdk.api.common.DeltaHeaders.CVT_IDENTITY_ID;

interface DeltaApi {

    @POST("identities")
    Call<CreateIdentityResponse> createIdentity(@Body CreateIdentityRequest request);

    @GET("identities/{id}")
    Call<GetIdentityResponse> getIdentity(@Header(CVT_IDENTITY_ID) String requestor,
                                          @Path("id") String id);

    @POST("secrets")
    Call<CreateSecretResponse> createSecret(@Header(CVT_IDENTITY_ID) String requestor,
                                            @Body CreateSecretRequest request);

    @GET("secrets/{id}")
    Call<GetSecretResponse> getSecret(@Header(CVT_IDENTITY_ID) String requestor,
                                      @Path("id") String id);

    @GET("secrets/{id}/content")
    Call<String> getSecretContent(@Header(CVT_IDENTITY_ID) String requestor,
                                  @Path("id") String id);

    @GET("secrets/{id}/metadata")
    Call<Map<String, String>> getSecretMetadata(@Header(CVT_IDENTITY_ID) String requestor,
                                                @Path("id") String id);

    @PUT("secrets/{id}/metadata")
    Call<Void> updateSecretMetadata(@Header(CVT_IDENTITY_ID) String requestor,
                                    @Header("If-Match") long version,
                                    @Path("id") String id,
                                    @Body Map<String, String> metadata);

    @POST("secrets")
    Call<ShareSecretResponse> shareSecret(@Header(CVT_IDENTITY_ID) String requestor,
                                          @Body ShareSecretRequest request);

    @DELETE("secrets/{id}")
    Call<Void> deleteSecret(@Header(CVT_IDENTITY_ID) String requestor,
                            @Path("id") String id);

    @GET("events/?purpose=AUDIT")
    Call<List<GetEventResponse>> getEvents(@Header(CVT_IDENTITY_ID) String requestor,
                                           @Query("secretId") String secretId,
                                           @Query("rsaKeyOwner") String rsaKeyOwner);

    @GET("secrets")
    Call<List<GetSecretsResponse>> getDerivedSecrets(@Header(CVT_IDENTITY_ID) String requestor,
                                                     @Query("baseSecret") String secretId,
                                                     @Query("createdBy") String ownerId,
                                                     @Query("page") int page,
                                                     @Query("pageSize") int pageSize);

    @GET("identities")
    Call<List<GetIdentityResponse>> getIdentitiesByMetadata(@Header(CVT_IDENTITY_ID) String requestor,
                                                            @QueryMap Map<String, String> metadata,
                                                            @Query("page") int page,
                                                            @Query("pageSize") int pageSize);

    @PUT("identities/{id}")
    Call<Void> updateIdentityMetadata(@Header(CVT_IDENTITY_ID) String requestor,
                                      @Header("If-Match") long version,
                                      @Path("id") String id,
                                      @Body UpdateIdentityMetadataRequest request);

    @GET("secrets/?baseSecret=false")
    Call<List<GetSecretsResponse>> getBaseSecrets(@Header(CVT_IDENTITY_ID) String requestor,
                                                  @Query("createdBy") String createdBy,
                                                  @QueryMap Map<String, String> metadata,
                                                  @Query("page") int page,
                                                  @Query("pageSize") int pageSize);

    @GET("secrets/?baseSecret=true")
    Call<List<GetSecretsResponse>> getDerivedSecrets(@Header(CVT_IDENTITY_ID) String requestor,
                                                     @Query("createdBy") String createdBy,
                                                     @Query("rsaKeyOwner") String rsaKeyOwner,
                                                     @QueryMap Map<String, String> metadata,
                                                     @Query("page") int page,
                                                     @Query("pageSize") int pageSize);

    @GET("secrets")
    Call<List<GetSecretsResponse>> getDerivedSecrets(@Header(CVT_IDENTITY_ID) String requestor,
                                                     @Query("baseSecret") String baseSecret,
                                                     @Query("createdBy") String createdBy,
                                                     @Query("rsaKeyOwner") String rsaKeyOwner,
                                                     @QueryMap Map<String, String> metadata,
                                                     @Query("page") int page,
                                                     @Query("pageSize") int pageSize);

}
