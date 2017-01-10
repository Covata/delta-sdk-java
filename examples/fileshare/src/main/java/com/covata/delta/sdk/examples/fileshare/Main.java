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

package com.covata.delta.sdk.examples.fileshare;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {
    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private static final String CMD_LINE_SYNTAX = "java -cp \"<path_to_fileshare_libs>/*\" " +
            "com.covata.delta.sdk.examples.fileshare.Main";

    private static final Options OPTIONS = new Options();

    private static final HelpFormatter HELP = new HelpFormatter();

    static {
        Option passPhrase = Option.builder("p").longOpt("passphrase")
                .required().hasArg().argName("pass phrase")
                .desc("The pass phrase for the local key store").build();
        Option keyStoreLoc = Option.builder("k").longOpt("keystore")
                .required().hasArg().argName("pass phrase")
                .desc("The path to the local key store").build();
        Option register = Option.builder("r").longOpt("register")
                .desc("Register a new identity").build();
        Option identity = Option.builder("i").longOpt("identity")
                .hasArg().argName("identity id")
                .desc("The authenticating Delta identity id").build();
        Option encrypt = Option.builder("e").longOpt("encrypt")
                .hasArg().argName("filename")
                .desc("Encrypt the specified file").build();
        Option decrypt = Option.builder("d").longOpt("decrypt")
                .hasArg().argName("filename")
                .desc("Decrypt the specified file").build();
        Option secret = Option.builder("s").longOpt("secret")
                .hasArg().argName("secret id")
                .desc("The Delta secret id").build();
        Option target = Option.builder("t").longOpt("target")
                .hasArg().argName("target identity id")
                .desc("Target identity id").build();

        OPTIONS.addOption(passPhrase);
        OPTIONS.addOption(keyStoreLoc);
        OPTIONS.addOption(register);
        OPTIONS.addOption(identity);
        OPTIONS.addOption(encrypt);
        OPTIONS.addOption(decrypt);
        OPTIONS.addOption(identity);
        OPTIONS.addOption(secret);
        OPTIONS.addOption(target);

        HELP.setOptionComparator(null);
    }

    private static void processCli(CommandLine cli) throws FileShareException {
        FileShare fs = new FileShare(cli.getOptionValue("p"), cli.getOptionValue("k"));
        if (cli.hasOption("r")) {
            fs.registerIdentity();
        } else if (cli.hasOption("i")) {
            fs.setIdentity(cli.getOptionValue("i"));
            if (cli.hasOption("e")) {
                String secretId = fs.encryptFile(cli.getOptionValue("e"));
                if (cli.hasOption("t")) {
                    fs.share(secretId, cli.getOptionValue("t"));
                }
            }
            if (cli.hasOption("s") && cli.hasOption("t")) {
                fs.share(cli.getOptionValue("s"), cli.getOptionValue("t"));
            }
            if (cli.hasOption("d")) {
                if (cli.hasOption("s")) {
                    fs.decryptFile(cli.getOptionValue("d"), cli.getOptionValue("s"));
                } else {
                    fs.decryptFile(cli.getOptionValue("d"));
                }
            }
        } else {
            LOG.error("A registered identity id must be provided to authenticate this action");
        }
    }

    public static void main(String[] args) {
        CommandLineParser parser = new DefaultParser();
        try {
            processCli(parser.parse(OPTIONS, args));
            System.exit(0);
        } catch (FileShareException e) {
            LOG.error("Execution failed with error", e);
        } catch (ParseException e) {
            HELP.printHelp(CMD_LINE_SYNTAX, OPTIONS, true);
        }
        System.exit(1);
    }

}
