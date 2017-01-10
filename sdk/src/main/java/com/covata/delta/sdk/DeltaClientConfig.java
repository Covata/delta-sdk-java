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

package com.covata.delta.sdk;

import com.covata.delta.sdk.api.DeltaApiClient;
import com.covata.delta.sdk.crypto.DeltaKeyStore;
import com.covata.delta.sdk.crypto.CryptoService;
import com.covata.delta.sdk.exception.DeltaClientException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.URL;
import java.nio.charset.Charset;
import java.security.Security;

/**
 * This class encapsulates parameters to allow programmatic configuration of
 * the <code>DeltaClient</code>. Use a {@link DeltaClientConfigBuilder} to
 * construct this object (via the {@link #builder()} factory method).
 */
public class DeltaClientConfig {

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private static final String DEFAULT_API_URL = "https://delta.covata.io/v1/";

    private static final Charset STRING_ENCODING_CHARSET = Charset.forName("UTF-8");

    private static final String DEFAULT_KEYSTORE_FILENAME = "DeltaJavaClientKeyStore.jks";

    private static final String DEFAULT_ASYM_KEY_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static final String DEFAULT_SYM_KEY_ALGORITHM = "AES/GCM/NoPadding";

    private static final String DEFAULT_RAND_ALGORITHM = "SHA1PRNG";

    private static final int MAX_SECRET_SIZE_BYTES_BASE64 = 200 * 1024;

    private static final int LOOKUP_PAGE_SIZE = 25;

    private static final int DEFAULT_CONNECTION_TIMEOUT_SECONDS = 20;

    private final String apiUrl;

    private final DeltaKeyStore keyStore;

    private final CryptoService cryptoService;

    private final DeltaApiClient apiClient;

    private final int connectionTimeoutSeconds;

    private boolean loggingEnabled = false;

    private String keyStorePassword;

    private String keyStoreBasePath;

    private String keyStoreFileName;

    private String asymmetricKeyAlgorithm;

    private String symmetricKeyAlgorithm;

    private String randomGenAlgorithm;

    private int maxSecretSizeBytesBase64 = MAX_SECRET_SIZE_BYTES_BASE64;

    private DeltaClientConfig(DeltaClientConfigBuilder builder) {
        this.apiUrl = builder.apiUrl;
        this.keyStorePassword = builder.keyStorePassword;
        this.keyStoreBasePath = builder.keyStoreBasePath;
        this.keyStoreFileName = builder.keyStoreFileName;
        this.loggingEnabled = builder.loggingEnabled;
        this.maxSecretSizeBytesBase64 = builder.maxSecretSizeBytesBase64;
        this.connectionTimeoutSeconds = builder.connectionTimeoutSeconds;
        this.asymmetricKeyAlgorithm = builder.asymmetricKeyAlgorithm;
        this.symmetricKeyAlgorithm = builder.symmetricKeyAlgorithm;
        this.randomGenAlgorithm = builder.randomGenAlgorithm;
        this.keyStore = builder.keyStore != null ? builder.keyStore :
                new DeltaKeyStore(this);
        this.apiClient = builder.apiClient != null ? builder.apiClient :
                new DeltaApiClient(this, keyStore);
        this.cryptoService = builder.cryptoService != null ? builder.cryptoService :
                new CryptoService(this, keyStore);
    }



    public DeltaKeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * Gets the cryptography service to be used by the client.
     *
     * @return the cryptography service
     */
    public CryptoService getCryptoService() {
        return cryptoService;
    }

    /**
     * Gets the API client to be used by the client.
     *
     * @return the API client
     */
    public DeltaApiClient getApiClient() {
        return apiClient;
    }

    /**
     * Gets the filename of the Java key store that will be used by the
     * Delta client. Default to <i>DeltaJavaClientKeyStore.jks</i> if not
     * set explicitly.
     *
     * @return the file name for the key store
     */
    public String getKeystoreFilename() {
        return keyStoreFileName;
    }

    /**
     * Returns the encoding character set to be used in the Delta client. The
     * encoding character set is <i>UTF-8</i>.
     *
     * @return the encoding character set
     */
    public Charset getEncodingCharset() {
        return STRING_ENCODING_CHARSET;
    }

    /**
     * Gets the URL of the Delta API end points.
     *
     * @return the URL of the Delta API end points
     */
    public String getApiUrl() {
        return apiUrl;
    }

    /**
     * Returns true if logging flag is enabled.
     *
     * @return true if enabled
     */
    public boolean isLoggingEnabled() {
        return loggingEnabled;
    }

    /**
     * Gets the password that can access the key store.
     *
     * @return the key store password
     */
    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    /**
     * Gets the path to the Java key store that will be used by the Delta
     * client.
     *
     * @return the path to the key store
     */
    public String getKeyStoreBasePath() {
        return keyStoreBasePath;
    }

    /**
     * Gets the maximum size, in bytes, of the contents (encoded in base 64)
     * for a secret in Delta.
     *
     * @return the maximum size, in bytes, of the base 64 encoded secret contents
     */
    public int getMaxSecretSizeBytesBase64() {
        return maxSecretSizeBytesBase64;
    }

    /**
     * Gets the page size for the paginated results returned in lookup queries
     * aganst the Delta API.
     *
     * @return the lookup page size
     */
    public int getLookupPageSize() {
        return LOOKUP_PAGE_SIZE;
    }

    /**
     * Gets the connection timeout (in seconds) for all HTTP connections to
     * the Delta service. The default is 20 seconds.
     *
     * @return the connection timeout value (in seconds)
     */
    public int getConnectionTimeoutSeconds() {
        return connectionTimeoutSeconds;
    }

    /**
     * Gets the symmetric key algorithm to be used in the encryption of
     * secrets. Defaults to <i>RSA/ECB/OAEPWithSHA-256AndMGF1Padding</i>
     * unless set explicitly.
     *
     * @return the asymmetric key algorithm
     */
    public String getAsymmetricKeyAlgorithm() {
        return asymmetricKeyAlgorithm;
    }

    /**
     * Sets the symmetric key algorithm to be used in the encryption of
     * secrets. Defaults to <i>AES/GCM/NoPadding</i> unless set explicitly.
     *
     * @return the symmetric key algorithm
     */
    public String getSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }

    /**
     * Sets the random number generator to be used by the client. Defaults to
     * <i>SHA1PRNG</i> unless set explicitly.
     *
     * @return the random number generator algorithm
     */
    public String getRandomGenAlgorithm() {
        return randomGenAlgorithm;
    }

    /**
     * Gets an instance of a builder to facility construction of a
     * configuration object for the Delta client.
     *
     * @return a configuration builder
     */
    public static DeltaClientConfigBuilder builder() {
        return new DeltaClientConfigBuilder();
    }

    /**
     * This builder should be used for construction of the Delta client
     * configuration object. Call the {@link #builder()} factory method to
     * get an instance of this builder.
     */
    public static class DeltaClientConfigBuilder {

        private String apiUrl = DEFAULT_API_URL;

        private DeltaKeyStore keyStore;

        private CryptoService cryptoService;

        private DeltaApiClient apiClient;

        private boolean loggingEnabled = false;

        private String keyStorePassword;

        private String keyStoreBasePath;

        private String keyStoreFileName = DEFAULT_KEYSTORE_FILENAME;

        private int connectionTimeoutSeconds = DEFAULT_CONNECTION_TIMEOUT_SECONDS;

        private int maxSecretSizeBytesBase64 = MAX_SECRET_SIZE_BYTES_BASE64;

        private String asymmetricKeyAlgorithm = DEFAULT_ASYM_KEY_ALGORITHM;

        private String symmetricKeyAlgorithm = DEFAULT_SYM_KEY_ALGORITHM;

        private String randomGenAlgorithm = DEFAULT_RAND_ALGORITHM;

        private DeltaClientConfigBuilder() {
        }

        /**
         * Sets the Delta API URL to be used by this client.
         *
         * @param apiUrl the URL of the Delta API
         * @return this builder
         */
        public DeltaClientConfigBuilder withApiUrl(String apiUrl) {
            try {
                new URL(apiUrl);
            } catch (Exception e) {
                throw new DeltaClientException("invalid url parameter specified", e);
            }
            this.apiUrl = apiUrl;
            return this;
        }

        /**
         * Sets the password that can access the key store specified by in
         * the {@link #withKeyStoreFileName(String)} method.
         *
         * @param password the key store password
         * @return this builder
         */
        public DeltaClientConfigBuilder withKeyStorePassword(String password) {
            keyStorePassword = password;
            return this;
        }

        /**
         * Sets the filename of the Java key store that will be used by the
         * Delta client. The password to access this key store should be
         * specified with the {@link #withKeyStorePassword(String)} method. The
         * file name will default to <i>DeltaJavaClientKeyStore.jks</i> if this
         * method is not called.
         *
         * @param name the file name for the key store
         * @return this builder
         */
        public DeltaClientConfigBuilder withKeyStoreFileName(String name) {
            keyStoreFileName = name;
            return this;
        }

        /**
         * Sets the path to the Java key store that will be used by the Delta
         * client.
         *
         * @param path the path to the key store
         * @return this builder
         */
        public DeltaClientConfigBuilder withKeyStorePath(String path) {
            keyStoreBasePath = path;
            return this;
        }

        /**
         * Sets logging to be enabled or disabled for the Delta client.
         *
         * @param enabled true if enabled
         * @return this builder
         */
        public DeltaClientConfigBuilder withLogging(boolean enabled) {
            loggingEnabled = enabled;
            return this;
        }

        /**
         * Sets the connection timeout (in seconds) for all HTTP connections to
         * the Delta service. The default is 20 seconds.
         *
         * @param connectionTimeoutSeconds the connection timeout value (in seconds)
         * @return this builder
         */
        public DeltaClientConfigBuilder withConnectionTimeoutSeconds(int connectionTimeoutSeconds) {
            this.connectionTimeoutSeconds = connectionTimeoutSeconds;
            return this;
        }

        /**
         * Sets the asymmetric key algorithm to be used in the generation of
         * encryption and signing keys for identities. The default algorithm
         * will default to <i>AES/GCM/NoPadding</i>.
         *
         * @param asymmetricKeyAlgorithm the asymmetric key algorithm
         * @return this builder
         */
        public DeltaClientConfigBuilder withAsymmetricKeyAlgorithm(String asymmetricKeyAlgorithm) {
            this.asymmetricKeyAlgorithm = asymmetricKeyAlgorithm;
            return this;
        }

        /**
         * Sets the symmetric key algorithm to be used in the encryption of
         * secrets. All encryption and decryption is done client-side, and will
         * default to <i>RSA/ECB/OAEPWithSHA-256AndMGF1Padding</i>.
         *
         * @param symmetricKeyAlgorithm the symmetric key algorithm
         * @return this builder
         */
        public DeltaClientConfigBuilder withSymmetricKeyAlgorithm(String symmetricKeyAlgorithm) {
            this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            return this;
        }

        /**
         * Sets the random number generator to be used by the client. Will
         * default to <i>SHA1PRNG</i>. This value should be set based on your
         * cryptographic strength requirements and available environmental
         * resources required to generate such numbers.
         *
         * @param randomGenAlgorithm the random number generator algorithm
         * @return this builder
         */
        public DeltaClientConfigBuilder withRandomGenAlgorithm(String randomGenAlgorithm) {
            this.randomGenAlgorithm = randomGenAlgorithm;
            return this;
        }

        /**
         * Sets the key store to be used by the client. If no key store has been
         * set in the configuration, a new <code>DeltaKeyStore</code> will be
         * instantiated based on other configuration parameters.
         *
         * @param keyStore the key store
         * @return this builder
         */
        public DeltaClientConfigBuilder withKeyStore(DeltaKeyStore keyStore) {
            this.keyStore = keyStore;
            return this;
        }

        /**
         * Sets the cryptography service to be used by the client. If no
         * cryptography service has been set in the configuration, a new
         * <code>CryptoService</code> will be instantiated based on other
         * configuration parameters.
         *
         * @param cryptoService the cryptography service
         * @return this builder
         */
        public DeltaClientConfigBuilder withCryptoService(CryptoService cryptoService) {
            this.cryptoService = cryptoService;
            return this;
        }

        /**
         * Sets the API client to be used by the client. If no API client has
         * been set in the configuration, a new <code>DeltaApiClient</code> will
         * be instantiated based on other configuration parameters.
         *
         * @param apiClient the API client
         * @return this builder
         */
        public DeltaClientConfigBuilder withApiClient(DeltaApiClient apiClient) {
            this.apiClient = apiClient;
            return this;
        }

        /**
         * Executes the builder to construct a new <code>DeltaClientConfig</code>.
         *
         * @return the new configuration
         */
        public DeltaClientConfig build() {
            return new DeltaClientConfig(this);
        }

    }
}
