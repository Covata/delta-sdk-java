# Covata Delta Java SDK
[![Build Status](https://travis-ci.org/Covata/delta-sdk-java.svg?branch=master)](https://travis-ci.org/Covata/delta-sdk-java)

Covata Delta provides an easy to use framework for sharing secrets across networks, and organisations.

## Prerequisites

* [Java 1.8+](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html "Java SE Development Kit 8 Downloads")
* [JCE Unlimited Strength Jurisdiction Policy](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
* [Gradle](https://gradle.org/ "Gradle Build Tool")

## Quick Start

Open a new terminal and perform the following steps.

Check out the code:
```
git clone https://github.com/Covata/delta-sdk-java.git
```

Go to the project root directory:
```
cd delta-sdk-java
```

Build the project and run the tests:
```
./gradlew clean build test
```

Run the file sharing example to register a new identity (you should get back an identifier for the newly created identity):
```
java -cp "./examples/fileshare/build/libs/*" com.covata.delta.sdk.examples.fileshare.Main -p passPhrase -k /path/to/keystore/ -r
```

Congratulations! You are now using Covata Delta. See the File Sharing Example section for more things to try.

## Downloading the Distribution
 
You can download the [latest release](https://github.com/Covata/delta-sdk-java/releases "Covata Delta SDK (Java)") and integrate the Delta SDK directly into your Java application. 

You will also need to include the relevant dependencies into your class path. See the [build.gradle](https://github.com/Covata/delta-sdk-java/blob/master/build.gradle "build.gradle") for required dependencies.

## Examples

The SDK source comes with a number of examples that demonstrate how it can be used. You can use the examples to test our Covata Delta or use them as reference for building your own applications. It is recommended that you clone this repository to get the examples, as they are not packaged in our release distributions. 

### File Sharing

The File Sharing example shows how to use the SDK to facilitate the sharing of encryption keys to protect files on disk. These files can be shared with other registered identities in Delta (such as via a USB key or a third party storage service), and they can access the encryption keys that protect the file via their own private keys.

To register a new identity - the identifier for the newly created identity is printed:
```
java -cp "./examples/fileshare/build/libs/*" com.covata.delta.sdk.examples.fileshare.Main -p passPhrase -k /path/to/keystore/ -r
```

To encrypt a file and store the encryption key as a secret inside Delta (the encrypted file will be stored as a .cvt file on your local file system, and the corresponding identifier for the newly created secret will be printed):
```
java -cp "./examples/fileshare/build/libs/*" com.covata.delta.sdk.examples.fileshare.Main -p passPhrase -k /path/to/keystore/ -i your-identity-id -e /your/file.name
```

Share this file with another identity (you will need to know the secret id, and the other user's identity id) - the identifier of the shared secret is printed:
```
java -cp "./examples/fileshare/build/libs/*" com.covata.delta.sdk.examples.fileshare.Main -p passPhrase -k /path/to/keystore/ -i your-identity-id -s the-secret-id -t their-identity-id
```

You can also encrypt and share a file in a single command (you will need to know the other user's identity id) - a .cvt file is also created on your local file system and the both the identifier of the secret and the shared secret are printed):
```
java -cp "./examples/fileshare/build/libs/*" com.covata.delta.sdk.examples.fileshare.Main -p passPhrase -k /path/to/keystore/ -i your-identity-id -e /your/file.name -t their-identity-id
```


To decrypt a file you have received from another identity (you will need to ensure they have shared the secret with you in Delta, and you have the encrypted file on your local file system):
```
java -cp "./examples/fileshare/build/libs/*" com.covata.delta.sdk.examples.fileshare.Main -p passPhrase -k /path/to/keystore/ -i your-identity-id -d /the/file.name.cvt
```

You can now experiment with the file sharing example to encrypt and share other  files on your computer with other identities.
```
usage: java -cp "<path_to_fileshare_libs>/*"
       com.covata.delta.sdk.examples.fileshare.Main -p <pass phrase> -k
       <pass phrase> [-r] [-i <identity id>] [-e <filename>] [-d
       <filename>] [-s <secret id>] [-t <target identity id>]
 -p,--passphrase <pass phrase>      The pass phrase for the local key store
 -k,--keystore <pass phrase>        The path to the local key store
 -r,--register                      Register a new identity
 -i,--identity <identity id>        The authenticating Delta identity id
 -e,--encrypt <filename>            Encrypt the specified file
 -d,--decrypt <filename>            Decrypt the specified file
 -s,--secret <secret id>            The Delta secret id
 -t,--target <target identity id>   Target identity id
 ```
 
### Hello World 
This example demonstrates the basics of creating identities, storing and sharing secrets.

You will need to have a folder called "keystore" in your home directory. A keystore with the pass-phrase "passPhrase" should exist or will be created as a result of running this example. To run this example from the command line:
```
java -cp "./examples/helloworld/build/libs/*" com.covata.delta.sdk.examples.helloworld.Main
```

### Multi-Share

The multi-share example demonstrates one producer (A) sharing a number of secrets to two recipients (B and C). At the end of the example, each recipient will output the secrets that have been shared with them, including the contents.

You will need to have a folder called "keystore" in your home directory. A keystore with the pass-phrase "passPhrase" should exist or will be created as a result of running this example. To run this example from the command line:
```
java -cp "./examples/multishare/build/libs/*" com.covata.delta.sdk.examples.multishare.MultiShare ./examples/multishare/build/resources/main/input.json
```
The input file consists of JSON defining the data flowing from the producer to the recipients:
```
[
  {"recipients": ["B", "C"], "content": "There was a boy called Eustace Clarence Scrubb, and he almost deserved it."},
  {"recipients": ["B"], "content": "The Man in Black fled across the desert, and the Gunslinger followed."},
  {"recipients": ["C"], "content": "The sun shone, having no alternative, on the nothing new."},
  {"recipients": ["B", "C"], "content": "It was a bright cold day in April, and the clocks were striking thirteen."}
]
```

## License

Copyright 2016 Covata Limited or its affiliates - Released under the [Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
