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

package com.covata.delta.sdk.model;

import com.covata.delta.sdk.exception.DeltaServiceException;

import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

class DeltaModelTestUtil {

    /**
     * Retry the runnable task up to max retries
     * and skip the exception if exceptionFilter evaluates true.
     * The method terminates when either an exception is caught or max retries
     * is reached
     *
     * @param maxRetries maximum number of retries
     * @param task the runnable task to be executed
     * @param retryPredicate retry if predicate evaluates true
     * @return number of retries until first success or maxRetries if failure kept occurring
     */
    static int getRetriesUntilFirstSuccess(final int maxRetries, Runnable task,
                                                  final Predicate<DeltaServiceException> retryPredicate) {
        int retries = 0;

        while (retries++ < maxRetries) {
            Optional<DeltaServiceException> optionalException = Optional.empty();
            try {
                task.run();
            } catch (DeltaServiceException ex) {
                optionalException = Stream.of(ex)
                        .filter(retryPredicate)
                        .findAny();
            }
            if (!optionalException.isPresent()) {
                break;
            }
        }

        return retries;
    }
}
