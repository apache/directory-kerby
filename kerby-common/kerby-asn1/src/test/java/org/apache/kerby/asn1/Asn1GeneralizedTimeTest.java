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
package org.apache.kerby.asn1;

import org.apache.kerby.asn1.type.Asn1GeneralizedTime;
import org.apache.kerby.asn1.util.HexUtil;
import org.junit.Test;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;

import static org.assertj.core.api.Assertions.assertThat;

public class Asn1GeneralizedTimeTest {

    @Test
    public void testEncoding() throws Exception {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssSSS");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        String dateInString = "2003070113328000";
        Date date = sdf.parse(dateInString);
        testEncodingWith(date, "0x18 0F 32 30 30 33 30 37 30 31 31 33 33 33 32 30 5A");
    }

    // https://issues.apache.org/jira/browse/DIRKRB-747
    @Test
    public void testEncodingNonASCIILocale() throws Exception {
        Locale existingLocale = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("mni", "IN", "Beng"));
            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssSSS");
            sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
            String dateInString = "2003070113328000";
            Date date = sdf.parse(dateInString);
            testEncodingWith(date, "0x18 0F 32 30 30 33 30 37 30 31 31 33 33 33 32 30 5A");
        } finally {
            Locale.setDefault(existingLocale);
        }
    }

    private void testEncodingWith(Date value, String expectedEncoding) throws IOException {
        byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
        Asn1GeneralizedTime aValue = new Asn1GeneralizedTime(value);
        aValue.useDER();
        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }


}
