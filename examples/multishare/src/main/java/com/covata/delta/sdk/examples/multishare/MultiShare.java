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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * This example demonstrates one producer (A) sharing a number of secrets to
 * two recipients (B and C). At the end of the example, each recipient will
 * output the secrets that have been shared with them, including the contents.
 *
 * You will need to have a folder called "keystore" in your home directory. A
 * keystore with the pass-phrase "passPhrase" should exist or will be created
 * as a result of running this example.
 */
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

    private List<Data> messages;

    private final DeltaClient client;

    private DeltaIdentity producer;

    private Map<String, DeltaIdentity> recipients = new HashMap<>();

    private MultiShare() {
        DeltaClientConfig config = DeltaClientConfig.builder()
                .withKeyStorePassword("passPhrase")
                .withKeyStorePath("~/keystore/")
                .withLogging(false)
                .build();
        client = new DeltaClient(config);
    }

    private void loadMessages(String messagesFile) throws Exception {
        File file = new File(messagesFile);

        Gson gson = new Gson();
        JsonReader reader = new JsonReader(new InputStreamReader(
                new FileInputStream(file), "UTF-8"));

        messages = Arrays.asList(gson.fromJson(reader, Data[].class));
    }

    private void createIdentities() throws Exception {
        producer = createIdentity("A");
        messages.stream()
                .map(Data::getRecipients)
                .flatMap(Arrays::stream)
                .collect(Collectors.toSet())
                .forEach((x) -> recipients.put(x, createIdentity(x)));
    }

    private DeltaIdentity createIdentity(String externalId) {
        DeltaIdentity identity = client.createIdentity(externalId, Collections.emptyMap());
        System.out.println(String.format("Identity %s created; identity id = %s",
                externalId, identity.getId()));
        return identity;
    }

    private void createAndShareSecrets() throws Exception {
        for (Data message: messages) {
            DeltaSecret secret = producer.createSecret(message.getContent());
            System.out.println(String.format(
                    "Identity %s: Created a base secret; secret id = %s; content = '%s'",
                    producer.getExternalId(), secret.getId(), secret.getContent()));

            for (String externalId: message.getRecipients()) {
                String derivedSecretId = secret.shareWith(
                        recipients.get(externalId)).getId();
                System.out.println(String.format(
                        "  Identity %s: Shared a derived secret with Identity %s; derived secret id = %s",
                        producer.getExternalId(), externalId, derivedSecretId));
            }
        }
    }

    private void printSharedSecrets() throws Exception {
        for (DeltaIdentity identity: recipients.values()) {
            List<DeltaSecret> secrets = identity.retrieveSecretsSharedWithMe(1, 5);
            System.out.println(String.format(
                    "Identity %s has %d secrets shared with them:",
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

    private void run(String messagesFile) throws Exception {
        loadMessages(messagesFile);
        createIdentities();
        createAndShareSecrets();
        printSharedSecrets();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Running multi-share example...");
        MultiShare multiShare = new MultiShare();
        if (args.length == 1) {
            multiShare.run(args[0]);
        } else {
            System.out.println("Input file not specified.");
        }
    }
}
