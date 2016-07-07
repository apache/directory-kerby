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

import org.apache.kerby.xdr.type.XdrInteger;
import org.apache.kerby.xdr.util.HexUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class XdrIntegerTest {
    @Test
    public void testEncoding() throws IOException {
        testEncodingWith(0, "0x00 00 00 00");
        testEncodingWith(1, "0x00 00 00 01");
        testEncodingWith(2, "0x00 00 00 02");
        testEncodingWith(127, "0x00 00 00 7F");
        testEncodingWith(128, "0x00 00 00 80");
        testEncodingWith(-1, "0xFF FF FF FF");
        testEncodingWith(-127, "0xFF FF FF 81");
        testEncodingWith(-255, "0xFF FF FF 01");
        testEncodingWith(-32768, "0xFF FF 80 00");
        testEncodingWith(1234567890, "0x49 96 02 D2");
        testEncodingWith(2147483647, "0x7F FF FF FF");
        testEncodingWith(-2147483647, "0x80 00 00 01");
        testEncodingWith(-2147483648, "0x80 00 00 00");
    }

    private void testEncodingWith(int value, String expectedEncoding) throws IOException {
        byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
        XdrInteger aValue = new XdrInteger(value);

        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }


    @Test
    public void testDecoding() throws IOException {
        testDecodingWith(0, "0x00 00 00 00");
        testDecodingWith(1, "0x00 00 00 01");
        testDecodingWith(2, "0x00 00 00 02");
        testDecodingWith(127, "0x00 00 00 7F");
        testDecodingWith(128, "0x00 00 00 80");
        testDecodingWith(-1, "0xFF FF FF FF");
        testDecodingWith(-127, "0xFF FF FF 81");
        testDecodingWith(-255, "0xFF FF FF 01");
        testDecodingWith(-32768, "0xFF FF 80 00");
        testDecodingWith(1234567890, "0x49 96 02 D2");
        testDecodingWith(2147483647, "0x7F FF FF FF");
        testDecodingWith(-2147483647, "0x80 00 00 01");
        testDecodingWith(-2147483648, "0x80 00 00 00");
    }

    private void testDecodingWith(int expectedValue, String content) throws IOException {
        XdrInteger decoded = new XdrInteger();

        decoded.decode(HexUtil.hex2bytesFriendly(content));
        assertThat(decoded.getValue().intValue()).isEqualTo(expectedValue);
    }
}
