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

import org.apache.kerby.xdr.type.XdrString;
import org.apache.kerby.xdr.util.HexUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class XdrStringTest {
        @Test
        public void testEncoding() throws IOException {
            testEncodingWith("Hello, Kerby!", "0X00 00 00 0D 48 65 6C 6C 6F 2C 20 4B 65 72 62 79 21 00 00 00");
            testEncodingWith("sillyprog", "0X00 00 00 09 73 69 6C 6C 79 70 72 6F 67 00 00 00");
            testEncodingWith("(quit)", "0X00 00 00 06 28 71 75 69 74 29 00 00");
        }

        private void testEncodingWith(String value, String expectedEncoding) throws IOException {
            byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
            XdrString aValue = new XdrString(value);

            byte[] encodingBytes = aValue.encode();
            assertThat(encodingBytes).isEqualTo(expected);
        }


        @Test
        public void testDecoding() throws IOException {
            testDecodingWith("Hello, Kerby!", "0X00 00 00 0D 48 65 6C 6C 6F 2C 20 4B 65 72 62 79 21 00 00 00");
            testDecodingWith("sillyprog", "0X00 00 00 09 73 69 6c 6c 79 70 72 6f 67 00 00 00");
            testDecodingWith("(quit)", "0X00 00 00 06 28 71 75 69 74 29 00 00");
        }

        private void testDecodingWith(String expectedValue, String content) throws IOException {
            XdrString decoded = new XdrString();
            decoded.decode(HexUtil.hex2bytesFriendly(content));
            assertThat(decoded.getValue()).isEqualTo(expectedValue);
        }
}
