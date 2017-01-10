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

package com.covata.delta.sdk.exception;

/**
 * Base exception for all exceptions thrown by the SDK as a result of
 * operations on the client-side such as signing a request, parsing a
 * response from the server, or encryption-related functions.
 */
public class DeltaClientException extends RuntimeException {

    /**
     * Creates a new <code>DeltaClientException</code> with the specified
     * message.
     *
     * @param message an error message describing why this exception was thrown
     */
    public DeltaClientException(String message) {
        super(message);
    }

    /**
     * Creates a new <code>DeltaClientException</code> with the specified
     * root cause.
     *
     * @param cause the underlying cause of this exception
     */
    public DeltaClientException(Throwable cause) {
        super(cause);
    }


    /**
     * Creates a new <code>DeltaClientException</code> with the specified
     * message and root cause.
     *
     * @param message an error message describing why this exception was thrown
     * @param cause the underlying cause of this exception
     */
    public DeltaClientException(String message, Throwable cause) {
        super(message, cause);
    }

}
