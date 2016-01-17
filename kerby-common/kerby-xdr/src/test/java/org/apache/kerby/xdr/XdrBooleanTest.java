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

import org.apache.kerby.xdr.type.XdrBoolean;
import org.apache.kerby.xdr.util.HexUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class XdrBooleanTest {
    @Test
    public void testEncoding() throws IOException {
        testEncodingWith(true, "0x00 00 00 01");
        testEncodingWith(false, "0x00 00 00 00");
        //what about undefined codeBytes?
    }

    private void testEncodingWith(Boolean value, String expectedEncoding) throws IOException {
        byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
        XdrBoolean aValue = new XdrBoolean(value);

        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }

    @Test
    public void testDecoding() throws IOException {
        testDecodingWith(true, "0x00 00 00 01");
        testDecodingWith(false, "0x00 00 00 00");
        //what about undefined codeBytes?
    }

    private void testDecodingWith(Boolean expectedValue, String content) throws IOException {
        XdrBoolean decoded = new XdrBoolean();

        decoded.decode(HexUtil.hex2bytesFriendly(content));
        assertThat(decoded.getValue()).isEqualTo(expectedValue);
    }

}
