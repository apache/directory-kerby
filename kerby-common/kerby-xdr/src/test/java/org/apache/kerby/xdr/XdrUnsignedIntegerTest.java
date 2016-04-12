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
package org.apache.kerby.xdr;

import org.apache.kerby.xdr.type.XdrUnsignedInteger;
import org.apache.kerby.xdr.util.HexUtil;
import org.junit.Test;

import java.io.IOException;


import static org.assertj.core.api.Assertions.assertThat;

public class XdrUnsignedIntegerTest {
    @Test
    public void testEncoding() throws IOException {
        testEncodingWith("0", "0x00 00 00 00");
        testEncodingWith("1", "0x00 00 00 01");
        testEncodingWith("2", "0x00 00 00 02");
        testEncodingWith("1234567890", "0x49 96 02 D2");
        testEncodingWith("2147483647", "0x7F FF FF FF");
        testEncodingWith("2147483648", "0x80 00 00 00");
        testEncodingWith("4294967295", "0xFF FF FF FF");
    }

    private void testEncodingWith(String value, String expectedEncoding) throws IOException {
        byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
        XdrUnsignedInteger aValue = new XdrUnsignedInteger(value);

        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }


    @Test
    public void testDecoding() throws IOException {
        testDecodingWith("0", "0x00 00 00 00");
        testDecodingWith("1", "0x00 00 00 01");
        testDecodingWith("2", "0x00 00 00 02");
        testDecodingWith("1234567890", "0x49 96 02 D2");
        testDecodingWith("2147483647", "0x7F FF FF FF");
        testDecodingWith("2147483648", "0x80 00 00 00");
        testDecodingWith("4294967295", "0xFF FF FF FF");
    }

    private void testDecodingWith(String expectedValue, String content) throws IOException {
        XdrUnsignedInteger decoded = new XdrUnsignedInteger();

        decoded.decode(HexUtil.hex2bytesFriendly(content));
        assertThat(decoded.getValue().toString()).isEqualTo(expectedValue);
    }
}
