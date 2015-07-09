/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.asn1.type;

import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

public class Asn1UtcTime extends Asn1Simple<Date> {
    public Asn1UtcTime() {
        this(null);
    }

    public Asn1UtcTime(long time) {
        super(UniversalTag.UTC_TIME, new Date(time * 1000L));
    }

    public Asn1UtcTime(Date date) {
        super(UniversalTag.UTC_TIME, date);
    }

    protected void toValue() throws IOException {
        String dateStr = new String(getBytes(), StandardCharsets.US_ASCII);
        String fixedDateStr = dateStr;

        /*
         * Make sure fixed date str be of the complete pattern 'YYMMDDhhmmss+/-hhmm'
         */
        int strLen = fixedDateStr.length();
        if (strLen == 6) { // YYMMDD
            fixedDateStr += "000000+0000";
        } else if (strLen == 7) { // YYMMDDZ
            fixedDateStr = fixedDateStr.replace("Z", "000000+0000");
        } else if (strLen == 10) { // YYMMDDhhmm
            fixedDateStr += "00+0000";
        } else if (strLen == 11) { // YYMMDDhhmmZ
            fixedDateStr = fixedDateStr.replace("Z", "00+0000");
        } else if (strLen == 12) { // YYMMDDhhmmss
            fixedDateStr += "+0000";
        } else if (strLen == 13) { // YYMMDDhhmmZ
            fixedDateStr = fixedDateStr.replace("Z", "+0000");
        } else if (strLen != 17) {
            throw new IllegalArgumentException("Bad utc time string " + dateStr);
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmssZ");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        try {
            setValue(sdf.parse(fixedDateStr));
        } catch (ParseException e) {
            throw new IOException("Failed to parse " + dateStr + " as utc time", e);
        }
    }

    @Override
    protected void toBytes() {
        Date date = getValue();
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss'Z'");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));

        String str = sdf.format(date);
        byte[] bytes = str.getBytes(StandardCharsets.US_ASCII);
        setBytes(bytes);
    }
}
