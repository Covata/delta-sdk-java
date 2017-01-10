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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class DateTimeUtil {

    private static final Logger LOG = LoggerFactory.getLogger(DateTimeUtil.class);

    public static final String SERVER_DATE_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.sss'Z'";

    public static final String REQUEST_DATE_PATTERN = "yyyyMMdd'T'HHmmss'Z'";

    public static String formatDateToServerTime(Date date) {
        return formatDate(date, SERVER_DATE_PATTERN);
    }

    private static String formatDate(Date date, String datePattern) {
        if (date == null) {
            throw new IllegalArgumentException("Date is null");
        }
        DateFormat localDateFormat = new SimpleDateFormat(datePattern);
        localDateFormat.setLenient(true);
        return localDateFormat.format(date);
    }

    public static Date getDate(String dateStr) throws DeltaClientException {
        DateFormat df = new SimpleDateFormat(SERVER_DATE_PATTERN);
        df.setLenient(true);
        try {
            return df.parse(dateStr);
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new DeltaClientException("Error getting date from string");
        }
    }

    public static String formatDateToRequestDateTime(Date date) {
        return formatDate(date, REQUEST_DATE_PATTERN);
    }

    public static Date getDateFromRequestDateTime(String dateStr) throws DeltaClientException {
        DateFormat df = new SimpleDateFormat(REQUEST_DATE_PATTERN);
        df.setLenient(true);
        try {
            return df.parse(dateStr);
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new DeltaClientException("Error getting request date time from string");
        }
    }

    public static Date getCurrentDate() {
        return new Date();
    }

    public static Date addDays(Date date, int numDays) {
        Calendar c = new GregorianCalendar();
        c.setTime(date);
        c.add(Calendar.DATE, numDays);
        return c.getTime();
    }

    public static String getRequestDateTime() {
        return DateTimeUtil.formatDateToRequestDateTime(new Date());
    }

}
