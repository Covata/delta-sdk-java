/*
 * Copyright (C) 2016 Covata Limited or its affiliates
 *
 *
 *  Information contained within this file cannot be copied,
 *  distributed and/or practised without the written consent of
 *  Covata Limited or its affiliates.
 */

package com.covata.delta.sdk.test.util;

import com.covata.delta.sdk.DeltaClientConfig;
import com.covata.delta.sdk.api.DeltaApiClient;
import com.covata.delta.sdk.crypto.DeltaKeyStore;
import com.covata.delta.sdk.crypto.CryptoService;
import com.covata.delta.sdk.exception.DeltaClientException;

import javax.crypto.SecretKey;
import java.security.KeyPair;

import static org.mockito.Mockito.mock;

/**
 * Provides shared instances of keys.
 * Key creation takes some time so reusing keys is a way to minimize test run time.
 */
public final class SharedTestKeys {

    public static final KeyPair SIGNING_KEY_PAIR;

    public static final KeyPair CRYPTO_KEY_PAIR;

    public static final SecretKey SECRET_KEY_A;

    public static final SecretKey SECRET_KEY_B;

    public static final String SIGNING_PRIVATE_KEY_BASE64 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCk2gVVEjuQEUFKvysoJS8i3hjc0cJ9OJtAZHqz0QsUbjQz0jvurUpbh5jJhAIlOFLRjNhTEwoEj/YUr3IGd1LFFDfezXbChUGh+TcptCGr97BQuMEAiP1kPT+YtS8QYtfwTq13DvP4WZ9ql129m8dfrBPXO/eBd0dSV3NLUiG1YIEnPWREJRAmV+FDWtxQYSBCa+JeUGRz3iRagL6oqDPpc2mcdU4o7gvjfoYNgTtcJw5Qnn6vRsu1oFgs7GgAt3yHNzlv8Mg+HXqI7J7XlEv7n36iGUHdiRhmxWZSt7/yz/jvuB76jbgRZnctehxzQVVk/9Xb3GOFcOj4jpkEZX9VAgMBAAECggEAB9FfF125/WcUFZtjTJAW4CxwOWipNI8OrcsWFpj/UYS4bQy3UuZc9GJF2KiuAV3eb5miWK46d2TsYqa/XZcjEb2XuLU9wJPZPPk4qH2mayVf8zQP0xqsCajt7ywIg1psqzTP/Sl0YH6/lKqBA5Dzr5HVjwuE/VrOwxTqntPSTWumhd2tXc434QdfEWXsVW7H6xKLPTZTK1jWYzQxYZmvf/td5NKKXmhfY3TMamRHb2x5XDnnCE6ktOs83CffBISzhucSe/w5/1DChRy3Xuri442nIxKtQI1Ad21aI7C/yoiUqPYpt0TkDJ53KFKgsPGvyY7c6fxL3ERfD/mpLO01gQKBgQDsxOWTf+p2C+det5p2j6iZ5N/dyWL5tUm9WPnmX3r83h3VkOdEdeGPa8QNhVrHv8us9VYOUVDh/0YDNzTJQog+QeV205NGQ272C2oRwkfo6ltHk/0DEjyPFSw0viyPSoBN0gytRqULmA0ULXZ7LcL36zDrQlD0DUU3HJvG58NGyQKBgQCyPcFPU5Vlx3ll0YSezfj9e1N82/bws7Tgk+3r6A8kdNvZN/9xZ7QKJ6a2ihHfs8HIGCGfTLCj5nXcbERfc784Cx4/jvaMj2BICuqf5K4Xatab0FmAF9waOwtkO61/dd8OKPf9nE04C8HZDQvIg5FqDtdHcOt9QsbudBrr7VKeLQKBgCuq2MiOY/ink2GFrUhGkIrpilxGQynYxKPWYCib3Xv7nzb/RZf7wcEI2BzCRo7mkbLxgJCdcLRtt0TqjqK70ZLh5mc2+EeSMknQqxxhX4/WgUU/Rv+lAmRFPGTx2hgHXoh7v/jJObFctrTM+bgYJYhB6UDKd1G7jNNwRE63+ez5AoGAVhbp1YzDbgNoqTsHWUSW7KeybW442Y2S4Z3Rns3Y8nzW6xXW9Ulndjgsl6Ice/XwtNqi8rQx5Rgc+Tf51jirtT/5fi1o+/8MO/+5zzy+sWTS/zMk52+eybSXDfSdGiEueUJkdUQXL+jN2i4o8NJLW/SLGmB5/WhReT7u+eEItIkCgYEAronO5VDCjZXEhJGebUKbKACHamp5DVxqhWsDxUHEldqA7V0OISYOpfOuVMeE7mIAae6yAGXLIhpSALr2fIcKoAKj2iCuzUdHmS8U7xBD7F2XBDHTVltAnhxq+FPd32Sdl6G8uVi1MoBiLAsjvdXMfU36FnZNlJZI4mcx18XoeXU=";

    public static final String CRYPTO_PRIVATE_KEY_BASE64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCy0wN4O57QlkvHyzgcOQgNbUvyLJYjOgZJijQ2wlDCj2AIjnXdrNnjhSgnKEEbgxrHzUbUejE71yAZ6f4rVlIRZQCnkCtxSKB9qHG39foykvQ8G7MQsoswHjYvGnSsD8RnHYRD3truwARzLlww99F3MnUFaNMoE0AwyH4osmJXC4IWLeAqAFX+SWZzWXMTsWYPZ+bOnOSdUwqJ9q4f8McuH/t4TNGoT7TSwtZs+EHaFC2tG3uJZc82sENFGlfsJCOwfL+5vLBKLZC9r/3MEWZWP5Mtof7/0xT9JmL/1RyD6kjNW5oG4pveOSaD7TLDOx3j+ss3MuEd5sHNgF9+iyJjAgMBAAECggEAZJ9iC2yY78wydgj+2Lqqskt2+Z1nGglTclwHB20N3nyo0AfBgOv7axAJSQdYo2+BST5UBcmAHKjvUkWdlKss4MbRuHfiSgtQ64Q2AQqzL3QLZCs99j5RHdFSMe0UC6GPpWoxe7NRxBheKKXEkHVR8118BYA3mQxECW83thSyS0GodTYj3Bz/QrLKY1bqoy3sq4a9lqPGsn6P1Ar42VDMLpoOU8lEc9pxpQq0pc9wqIAQy8nJMxTF/EiDWf/EIOqdbJnPWwLawMCc3CurZkLSWHNxO46YiCvJkjsjqSLM93Z6lX1DgJLGfbbCa9VwP58E3A2n/c+tc4wojYJBh1L9MQKBgQDgAeOkgkYtqBcDH4FPY4owgM/94kNVDb7Yaoh2aqZ+4BVobPotZ4Obajfn5NyTgYe6dtka0U3Gyu95H5A5wjKiEfjsB9LLz/l6Bk/oN1BA256K+1O1OtgBcKaAjGEsyHPuD95uGlf6meYLMFcwfQhdRwDBGhMsel6imHQ1UQEW2QKBgQDMXSYl5a98MPIawUabiLf+Flrscnd4tLd+XM5dcV9Dv4U9bf/Jh+JPaCM8ADJ2H4IXLQzXWhCR3XdqTw8MmlC03Q+KtwrVenqGYTxAsPxtRXDgqW6BXpkVvgvtHKrzeODoJhzi2on74Jup3o1Esd+q0JgEqTrButa2KAMD04aVmwKBgQDJMSkyokdBzo0MowlTMoX1Vlx5HPV4uOXGHrj+EoADyGOx7N8uVKChv98Cik2KtnYfhYstSPvgJni7gxvYpJExe47k/4nWwK7DaFPwr22HMznMfjsKtRU5BeKl5m+I92kYUmxm24ZVcFBrkDlfNY2DqbgFt9OsySOiSedl06F00QKBgF5I63y4h0no2wn0+bpwTVLwxWopNW1/Etk9wAfkcmszRSmeQlCcXJD+HqNkA+PzjXVb13zTlKl3X8ywROUvnOSUyMLayCjNpRGycrX18cAINZexE8aj+kTJtX7jpwtFTZ5NVy5iXR7T9X1drBdxaRvJuRkNaopOxRitRRbS1FjZAoGBAId5AJEhbKCQLpEevELKDlSEIG/18D3t/Oe5xDpM0i6E4+Az1XvqlftL5ib3DX8AYap4JvPWPKzCi9YdIufLZB116BrhmQLkV7z+vd7/CsJIgLCimsI/8smdGvLaXvFRcR/VTUsy+h9MDzmcRZ1opVGSAkVsgKdxLk9P/FeqY6Cf";

    public static final String SIGNING_PUBLIC_KEY_BASE64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApNoFVRI7kBFBSr8rKCUvIt4Y3NHCfTibQGR6s9ELFG40M9I77q1KW4eYyYQCJThS0YzYUxMKBI/2FK9yBndSxRQ33s12woVBofk3KbQhq/ewULjBAIj9ZD0/mLUvEGLX8E6tdw7z+FmfapddvZvHX6wT1zv3gXdHUldzS1IhtWCBJz1kRCUQJlfhQ1rcUGEgQmviXlBkc94kWoC+qKgz6XNpnHVOKO4L436GDYE7XCcOUJ5+r0bLtaBYLOxoALd8hzc5b/DIPh16iOye15RL+59+ohlB3YkYZsVmUre/8s/477ge+o24EWZ3LXocc0FVZP/V29xjhXDo+I6ZBGV/VQIDAQAB";

    public static final String CRYPTO_PUBLIC_KEY_BASE64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstMDeDue0JZLx8s4HDkIDW1L8iyWIzoGSYo0NsJQwo9gCI513azZ44UoJyhBG4Max81G1HoxO9cgGen+K1ZSEWUAp5ArcUigfahxt/X6MpL0PBuzELKLMB42Lxp0rA/EZx2EQ97a7sAEcy5cMPfRdzJ1BWjTKBNAMMh+KLJiVwuCFi3gKgBV/klmc1lzE7FmD2fmzpzknVMKifauH/DHLh/7eEzRqE+00sLWbPhB2hQtrRt7iWXPNrBDRRpX7CQjsHy/ubywSi2Qva/9zBFmVj+TLaH+/9MU/SZi/9Ucg+pIzVuaBuKb3jkmg+0ywzsd4/rLNzLhHebBzYBffosiYwIDAQAB";

    public static final String SECRET_KEY_A_BASE64 = "Krh0AHsCNIjhLZv2nqc1YR77KwGRcxs2VgoL5wt/kSs=";

    public static final String SECRET_KEY_B_BASE64 = "M+fRNuTiIRwuiO7dXDSDYZen6k584bRoaUAYeTN84ME=";

    private static final String MOCK_API_URL = "https://test.com/v1/";

    static {
        try {
            DeltaClientConfig config = DeltaClientConfig.builder()
                    .withApiUrl(MOCK_API_URL)
                    .withApiClient(mock(DeltaApiClient.class))
                    .withKeyStore(mock(DeltaKeyStore.class))
                    .build();

            CryptoService cryptoService = config.getCryptoService();

            SIGNING_KEY_PAIR = new KeyPair(
                    cryptoService.getPublicKey(SIGNING_PUBLIC_KEY_BASE64),
                    cryptoService.getPrivateKey(SIGNING_PRIVATE_KEY_BASE64));
            CRYPTO_KEY_PAIR = new KeyPair(
                    cryptoService.getPublicKey(CRYPTO_PUBLIC_KEY_BASE64),
                    cryptoService.getPrivateKey(CRYPTO_PRIVATE_KEY_BASE64));
            SECRET_KEY_A = cryptoService.getSymmetricKey(SECRET_KEY_A_BASE64);
            SECRET_KEY_B = cryptoService.getSymmetricKey(SECRET_KEY_B_BASE64);
        } catch (DeltaClientException e) {
            throw new RuntimeException("Cannot create shared test keys", e);
        }

    }


    private SharedTestKeys() {
        //        prevent instantiation
    }
}
