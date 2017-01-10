/*
 * Copyright (C) 2016 Covata Limited or its affiliates
 *
 *
 *  Information contained within this file cannot be copied,
 *  distributed and/or practised without the written consent of
 *  Covata Limited or its affiliates.
 */

package com.covata.delta.sdk.api.request;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;

public class GetEventsRequestTest {

    @Test
    public void ensureEqualsAndHashcode() {
        EqualsVerifier.forClass(GetEventsRequest.class).verify();
    }
}
