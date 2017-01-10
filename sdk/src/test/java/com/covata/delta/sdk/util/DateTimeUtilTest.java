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

package com.covata.delta.sdk.util;

import com.covata.delta.sdk.exception.DeltaClientException;
import org.junit.Test;

import java.util.Calendar;
import java.util.Date;

import static org.junit.Assert.assertEquals;

public class DateTimeUtilTest {

    @Test
    public void shouldReturnDateWithTimeInServerFormat() {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, 2016);
        cal.set(Calendar.MONTH, Calendar.OCTOBER);
        cal.set(Calendar.DAY_OF_MONTH, 30);
        cal.set(Calendar.HOUR_OF_DAY, 15);
        cal.set(Calendar.MINUTE, 45);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        Date d = cal.getTime();

        String serverFormat = DateTimeUtil.formatDateToServerTime(d);

        assertEquals("2016-10-30T15:45:00.000Z", serverFormat);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionGivenNullDate() {
        DateTimeUtil.formatDateToServerTime(null);
    }

    @Test
    public void shouldReturnCorrectDateGivenServerDateTimeFormat() throws Exception {
        String serverDate = "2016-10-08T06:43:47.000Z";

        Date d = DateTimeUtil.getDate(serverDate);

        Calendar cal = Calendar.getInstance();
        cal.setTime(d);
        assertEquals(2016, cal.get(Calendar.YEAR));
        assertEquals(Calendar.OCTOBER, cal.get(Calendar.MONTH));
        assertEquals(8, cal.get(Calendar.DAY_OF_MONTH));
        assertEquals(Calendar.AM, cal.get(Calendar.AM_PM));
        assertEquals(6, cal.get(Calendar.HOUR_OF_DAY));
        assertEquals(43, cal.get(Calendar.MINUTE));
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionGivenDateStringWhichCannotBeParsed() throws Exception {
        DateTimeUtil.getDate("2016-10-08ABCT06:43:47.000Z");
    }

    @Test
    public void shouldReturnDateWithTimeInCvtDateRequestFormat() {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, 2016);
        cal.set(Calendar.MONTH, Calendar.MAY);
        cal.set(Calendar.DAY_OF_MONTH, 14);
        cal.set(Calendar.HOUR_OF_DAY, 20);
        cal.set(Calendar.MINUTE, 22);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        Date d = cal.getTime();

        String serverFormat = DateTimeUtil.formatDateToRequestDateTime(d);

        assertEquals("20160514T202200Z", serverFormat);
    }

    @Test
    public void shouldReturnCorrectDateGivenRequestDateTime() throws Exception {
        String requestDate = "20160905T123600Z";

        Date d = DateTimeUtil.getDateFromRequestDateTime(requestDate);

        Calendar cal = Calendar.getInstance();
        cal.setTime(d);
        assertEquals(2016, cal.get(Calendar.YEAR));
        assertEquals(Calendar.SEPTEMBER, cal.get(Calendar.MONTH));
        assertEquals(5, cal.get(Calendar.DAY_OF_MONTH));
        assertEquals(Calendar.PM, cal.get(Calendar.AM_PM));
        assertEquals(12, cal.get(Calendar.HOUR_OF_DAY));
        assertEquals(36, cal.get(Calendar.MINUTE));
    }

    @Test(expected = DeltaClientException.class)
    public void shouldThrowExceptionGivenRequestDateStringWhichCannotBeParsed() throws Exception {
        DateTimeUtil.getDateFromRequestDateTime("20160905T12YO3600Z");
    }

    @Test
    public void shouldAddDaysCorrectlyToDate() {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, 2016);
        cal.set(Calendar.MONTH, Calendar.FEBRUARY);
        cal.set(Calendar.DAY_OF_MONTH, 29);
        cal.set(Calendar.HOUR_OF_DAY, 9);
        cal.set(Calendar.MINUTE, 15);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        Date d = cal.getTime();

        Date addedDays = DateTimeUtil.addDays(d, 5);

        cal.set(Calendar.MONTH, Calendar.MARCH);
        cal.set(Calendar.DAY_OF_MONTH, 5);
        assertEquals(cal.getTime(), addedDays);
    }

}
