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

import org.apache.kerby.xdr.type.XdrStructType;
import org.apache.kerby.xdr.util.HexUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class XdrStructTypeTest {
    @Test
    public void testEncoding() throws IOException {
        MyFile file = new MyFile("sillyprog", FileType.EXEC);
        testEncodingWith(file, "0x00 00 00 09 73 69 6C 6C 79 70 72 6F 67 00 00 00 00 00 00 02");
    }

    private void testEncodingWith(MyFile value, String expectedEncoding) throws IOException {
        byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
        XdrFieldInfo[] fieldInfos = {new XdrFieldInfo(0, XdrDataType.STRING, value.getFileName()), new XdrFieldInfo(1, XdrDataType.ENUM,value.getType())};

        XdrStructType aValue = new XdrStructTypeInstance(fieldInfos);

        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }


    @Test
    public void testDecoding() throws IOException {
        MyFile file = new MyFile("sillyprog", FileType.EXEC);
        testDecodingWith(file, "0x00 00 00 09 73 69 6C 6C 79 70 72 6F 67 00 00 00 00 00 00 02");
    }

    private void testDecodingWith(MyFile expectedValue, String content) throws IOException {
        XdrStructType decoded = new XdrStructTypeInstance();

        decoded.decode(HexUtil.hex2bytesFriendly(content));

        XdrFieldInfo[] fieldInfos = decoded.getValue().getXdrFieldInfos();
        assertThat(fieldInfos.length).isEqualTo(2);
        assertThat(fieldInfos[0].getDataType()).isEqualTo(XdrDataType.STRING);
        assertThat((String) fieldInfos[0].getValue()).isEqualTo(expectedValue.getFileName());
        assertThat(fieldInfos[1].getDataType()).isEqualTo(XdrDataType.ENUM);
        assertThat((FileType) fieldInfos[1].getValue()).isEqualTo(expectedValue.getType());
    }

}
