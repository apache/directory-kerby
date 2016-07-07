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

import org.apache.kerby.xdr.type.XdrUnion;
import org.apache.kerby.xdr.util.HexUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class XdrUnionTest {
    @Test
    public void testEncoding() throws IOException {
        UnionFileTypeSwitch fileType = new UnionFileTypeSwitch(FileKind.EXEC);
        testEncodingWith(fileType, "0x00 00 00 02 00 00 00 04 6c 69 73 70");
    }

    private void testEncodingWith(UnionFileTypeSwitch value, String expectedEncoding) throws IOException {
        byte[] expected = HexUtil.hex2bytesFriendly(expectedEncoding);
        XdrFieldInfo[] fieldInfos = {new XdrFieldInfo(0, value.getFileKind(), value.getFileValue()),
                new XdrFieldInfo(1, value.getArmKind(), value.getArmValue())};

        XdrUnion aValue = new XdrUnionInstance(fieldInfos);

        byte[] encodingBytes = aValue.encode();
        assertThat(encodingBytes).isEqualTo(expected);
    }


    @Test
    public void testDecoding() throws IOException {
        UnionFileTypeSwitch fileType = new UnionFileTypeSwitch(FileKind.EXEC);
        testDecodingWith(fileType, "0x00 00 00 02 00 00 00 04 6c 69 73 70");
    }

    private void testDecodingWith(UnionFileTypeSwitch expectedValue, String content) throws IOException {
        XdrUnion decoded = new XdrUnionInstance();

        decoded.decode(HexUtil.hex2bytesFriendly(content));

        XdrFieldInfo[] fieldInfos = decoded.getValue().getXdrFieldInfos();
        assertThat(fieldInfos.length).isEqualTo(2);
        assertThat(fieldInfos[0].getDataType()).isEqualTo(expectedValue.getFileKind());
        assertThat((FileKind) fieldInfos[0].getValue()).isEqualTo(expectedValue.getFileValue());
        assertThat(fieldInfos[1].getDataType()).isEqualTo(expectedValue.getArmKind());
        assertThat((String) fieldInfos[1].getValue()).isEqualTo(expectedValue.getArmValue());
    }
}
