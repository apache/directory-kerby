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

import org.apache.kerby.xdr.type.XdrLong;
import org.apache.kerby.xdr.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class XdrLongTest {
    @Test
    public void testEncoding() throws IOException {
        testEncodingWith(0L, "0x00 00 00 00 00 00 00 00");
        testEncodingWith(1L, "0x00 00 00 00 00 00 00 01");
        testEncodingWith(2L, "0x00 00 00 00 00 00 00 02");
        testEncodingWith(127L, "0x00 00 00 00 00 00 00 7F");
        testEncodingWith(128L, "0x00 00 00 00 00 00 00 80");
        testEncodingWith(-1L, "0xFF FF FF FF FF FF FF FF");
        testEncodingWith(-127L, "0xFF FF FF FF FF FF FF 81");
        testEncodingWith(-255L, "0xFF FF FF FF FF FF FF 01");
        testEncodingWith(-32768L, "0xFF FF FF FF FF FF 80 00");
        testEncodingWith(1234567890L, "0x00 00 00 00 49 96 02 D2");
        testEncodingWith(9223372036854775807L, "0x7F FF FF FF FF FF FF FF");
        testEncodingWith(-9223372036854775807L, "0x80 00 00 00 00 00 00 01");
        testEncodingWith(-9223372036854775808L, "0x80 00 00 00 00 00 00 00");
    }

    private void testEncodingWith(long value, String expectedEncoding) throws IOException {
        byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
        XdrLong aValue = new XdrLong(value);

        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }


    @Test
    public void testDecoding() throws IOException {
        testDecodingWith(0L, "0x00 00 00 00 00 00 00 00");
        testDecodingWith(1L, "0x00 00 00 00 00 00 00 01");
        testDecodingWith(2L, "0x00 00 00 00 00 00 00 02");
        testDecodingWith(127L, "0x00 00 00 00 00 00 00 7F");
        testDecodingWith(128L, "0x00 00 00 00 00 00 00 80");
        testDecodingWith(-1L, "0xFF FF FF FF FF FF FF FF");
        testDecodingWith(-127L, "0xFF FF FF FF FF FF FF 81");
        testDecodingWith(-255L, "0xFF FF FF FF FF FF FF 01");
        testDecodingWith(-32768L, "0xFF FF FF FF FF FF 80 00");
        testDecodingWith(1234567890L, "0x00 00 00 00 49 96 02 D2");
        testDecodingWith(9223372036854775807L, "0x7F FF FF FF FF FF FF FF");
        testDecodingWith(-9223372036854775807L, "0x80 00 00 00 00 00 00 01");
        testDecodingWith(-9223372036854775808L, "0x80 00 00 00 00 00 00 00");
    }

    private void testDecodingWith(long expectedValue, String content) throws IOException {
        XdrLong decoded = new XdrLong();

        decoded.decode(HexUtil.hex2bytesFriendly(content));
        assertThat(decoded.getValue().longValue()).isEqualTo(expectedValue);
    }
}
