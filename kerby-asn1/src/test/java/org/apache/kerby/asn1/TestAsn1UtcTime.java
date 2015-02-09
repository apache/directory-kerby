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

import org.apache.kerby.asn1.type.Asn1UtcTime;
import org.junit.Test;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import static org.assertj.core.api.Assertions.assertThat;

public class TestAsn1UtcTime {

    @Test
    public void testEncoding() throws Exception {
        /**
         * Cryptography for Developers -> ASN.1 UTCTIME Type
         * the encoding of July 4, 2003 at 11:33 and 28 seconds would be
         “030704113328Z” and be encoded as 0x17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A.
         */
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        String dateInString = "2003-07-04 11:33:28";
        Date date = sdf.parse(dateInString);
        testEncodingWith(date, "0x17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A");
    }

    private void testEncodingWith(Date value, String expectedEncoding) {
        byte[] expected = Util.hex2bytes(expectedEncoding);
        Asn1UtcTime aValue = new Asn1UtcTime(value);
        aValue.getEncodingOption().useDer();
        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }

    @Test
    public void testDecoding() throws Exception {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String dateInString = "2003-07-04 11:33:28";
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse(dateInString);
        testDecodingWith(date, "0x17 0D 30 33 30 37 30 34 31 31 33 33 32 38 5A");
    }

    private void testDecodingWith(Date expectedValue, String content) throws IOException {
        Asn1UtcTime decoded = new Asn1UtcTime();
        decoded.getEncodingOption().useDer();
        decoded.decode(Util.hex2bytes(content));
        assertThat(decoded.getValue()).isEqualTo(expectedValue);
    }
}
