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

import org.apache.kerby.asn1.type.Asn1Boolean;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class TestAsn1Boolean {

    @Test
    public void testEncoding() {
        testEncodingWith(true, "0x01 01 FF", true);
        testEncodingWith(false, "0x01 01 00", true);
    }

    private void testEncodingWith(Boolean value, String expectedEncoding,
                                  boolean isDer) {
        byte[] expected = Util.hex2bytes(expectedEncoding);
        Asn1Boolean aValue = new Asn1Boolean(value);
        if (isDer) {
            aValue.getEncodingOption().useDer();
        } else {
            aValue.getEncodingOption().useBer();
        }
        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }

    @Test
    public void testDecoding() throws IOException {
        testDecodingWith(true, "0x01 01 FF", true);
        testDecodingWith(false, "0x01 01 7F", true);
        testDecodingWith(true, "0x01 01 7F", false);
        testDecodingWith(false, "0x01 01 00", true);
    }

    private void testDecodingWith(Boolean expectedValue, String content,
                                  boolean isDer) throws IOException {
        Asn1Boolean decoded = new Asn1Boolean();
        if (isDer) {
            decoded.getEncodingOption().useDer();
        } else {
            decoded.getEncodingOption().useBer();
        }
        decoded.decode(Util.hex2bytes(content));
        assertThat(decoded.getValue()).isEqualTo(expectedValue);
    }
}
