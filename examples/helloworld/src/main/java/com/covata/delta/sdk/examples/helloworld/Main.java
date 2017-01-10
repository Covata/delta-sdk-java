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

package com.covata.delta.sdk.examples.helloworld;

import com.covata.delta.sdk.DeltaClient;
import com.covata.delta.sdk.DeltaClientConfig;
import com.covata.delta.sdk.model.DeltaIdentity;
import com.covata.delta.sdk.model.DeltaSecret;


/**
 * This example demonstrates the basics of creating identities, storing and
 * sharing secrets. It assumes you have a folder called "keystore" in your
 * home directory.
 */
public class Main {

    public static void main(String[] args) {
        DeltaClientConfig config = DeltaClientConfig.builder()
                .withKeyStorePassword("passPhrase")
                .withKeyStorePath("~/keystore/")
                .withLogging(false)
                .build();

        DeltaClient client = new DeltaClient(config);

        DeltaIdentity identityA = client.createIdentity();
        System.out.println("Identity A created; identity id = " + identityA.getId());

        DeltaSecret secret = identityA.createSecret("Hello World!");
        System.out.println(String.format(
                "Identity A: Created a base secret; secret id = %s; content = %s",
                secret.getId(), secret.getContent()));

        DeltaIdentity identityB = client.createIdentity();
        System.out.println("Identity B created; identity id = " + identityB.getId());

        String derivedSecretId = secret.shareWith(identityB).getId();
        System.out.println("Identity A: Shared a derived secret with Identity B; derived secret id = " + derivedSecretId);

        DeltaSecret derivedSecret = identityB.retrieveSecret(derivedSecretId);
        System.out.println(String.format(
                "Identity B: Retrieved a derived secret; secret id = %s; content = %s",
                derivedSecret.getId(), derivedSecret.getContent()));
    }
}
