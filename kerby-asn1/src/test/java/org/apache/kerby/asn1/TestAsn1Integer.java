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

import org.apache.kerby.asn1.type.Asn1Integer;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class TestAsn1Integer {

    @Test
    public void testEncoding() {
        testEncodingWith(0, "0x02 01 00");
        testEncodingWith(1, "0x02 01 01");
        testEncodingWith(2, "0x02 01 02");
        testEncodingWith(127, "0x02 01 7F");
        testEncodingWith(128, "0x02 02 00 80");
        testEncodingWith(-1, "0x02 01 FF");
        testEncodingWith(-128, "0x02 01 80");
        testEncodingWith(-32768, "0x02 02 80 00");
        testEncodingWith(1234567890, "0x02 04 49 96 02 D2");
    }

    private void testEncodingWith(int value, String expectedEncoding) {
        byte[] expected = Util.hex2bytes(expectedEncoding);
        Asn1Integer aValue = new Asn1Integer(value);
        aValue.getEncodingOption().useDer();
        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }

    @Test
    public void testDecoding() throws IOException {
        testDecodingWith(0, "0x02 01 00");
        testDecodingWith(1, "0x02 01 01");
        testDecodingWith(2, "0x02 01 02");
        testDecodingWith(127, "0x02 01 7F");
        testDecodingWith(128, "0x02 02 00 80");
        testDecodingWith(-1, "0x02 01 FF");
        testDecodingWith(-128, "0x02 01 80");
        testDecodingWith(-32768, "0x02 02 80 00");
        testDecodingWith(1234567890, "0x02 04 49 96 02 D2");
    }

    private void testDecodingWith(int expectedValue, String content) throws IOException {
        Asn1Integer decoded = new Asn1Integer();
        decoded.getEncodingOption().useDer();
        decoded.decode(Util.hex2bytes(content));
        assertThat(decoded.getValue().intValue()).isEqualTo(expectedValue);
    }
}
