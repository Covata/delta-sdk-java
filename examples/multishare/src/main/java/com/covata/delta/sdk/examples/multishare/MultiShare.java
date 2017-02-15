/*
 * Copyright 2017 Covata Limited or its affiliates
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

package com.covata.delta.sdk.examples.multishare;

import com.covata.delta.sdk.DeltaClient;
import com.covata.delta.sdk.DeltaClientConfig;
import com.covata.delta.sdk.model.DeltaIdentity;
import com.covata.delta.sdk.model.DeltaSecret;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

public class MultiShare {



    private static class Data {
        private String[] recipients;
        private String content;

        public Data(String[] recipients, String content) {
            this.recipients = recipients;
            this.content = content;
        }

        String[] getRecipients() {
            return recipients;
        }

        String getContent() {
            return content;
        }
    }

    private final DeltaClient client;
    private Map<String, DeltaIdentity> identities = new HashMap<>();

    private MultiShare() {
        DeltaClientConfig config = DeltaClientConfig.builder()
                .withKeyStorePassword("passPhrase")
                .withKeyStorePath("~/keystore/")
                .withLogging(false)
                .build();
        client = new DeltaClient(config);
    }

    private void createIdentities() throws Exception {
        createIdentity("A");
        createIdentity("B");
        createIdentity("C");
    }

    private void createIdentity(String externalId) throws Exception {
        DeltaIdentity identity = client.createIdentity(externalId, Collections.emptyMap());
        System.out.println(String.format("Identity %s created; identity id = %s",
                externalId, identity.getId()));
        identities.put(externalId, identity);
    }

    private void createAndShareSecrets(Queue<Data> messages) throws Exception {
        while (!messages.isEmpty()) {
            Data message = messages.remove();
            DeltaSecret secret = identities.get("A").createSecret(message.getContent());
            System.out.println(String.format(
                    "Identity A: Created a base secret; secret id = %s; content = '%s'",
                    secret.getId(), secret.getContent()));

            for (String externalId: message.getRecipients()) {
                String derivedSecretId = secret.shareWith(
                        identities.get(externalId)).getId();
                System.out.println(String.format(
                        "  Identity A: Shared a derived secret with Identity %s; derived secret id = %s",
                        externalId, derivedSecretId));
            }
        }
    }

    private Queue<Data> loadMessages() throws Exception {
        File file = new File(getClass()
                .getClassLoader()
                .getResource("input.json")
                .getFile());

        Gson gson = new Gson();
        JsonReader reader = new JsonReader(new InputStreamReader(
                        new FileInputStream(file), "UTF-8"));

        return new LinkedList<>(
                Arrays.asList(gson.fromJson(reader, Data[].class)));
    }

    private void printSharedSecrets() throws Exception {
        for (DeltaIdentity identity: identities.values()) {
            List<DeltaSecret> secrets = client.getSecretsSharedWithMe(
                    identity.getId(), 1, 5);
            System.out.println(String.format(
                    "Identity %s has %d secrets shared with them.",
                    identity.getExternalId(), secrets.size()));
            for (DeltaSecret secretSharedWithMe: secrets) {
                System.out.println(String.format(
                        "  Derived secret id = %s; created by = %s; created date = %s; content = '%s'",
                        secretSharedWithMe.getId(),
                        secretSharedWithMe.getCreatedBy(),
                        secretSharedWithMe.getCreatedDate(),
                        secretSharedWithMe.getContent()));
            }
        }
    }

    private void run() throws Exception {
        createIdentities();
        createAndShareSecrets(loadMessages());
        printSharedSecrets();
    }

    public static void main(String[] args) throws Exception {
        MultiShare multiShare = new MultiShare();
        multiShare.run();
    }



}
