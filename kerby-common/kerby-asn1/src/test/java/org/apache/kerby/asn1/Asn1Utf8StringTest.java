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

import java.nio.charset.StandardCharsets;

import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Asn1Utf8StringTest {

    @Test
    public void testEncodingLength() throws Exception {

        // Testing length <= 127
        String input = "E-Tuğra EBG Bilişim Teknolojileri ve Hizmetleri A.Ş.";
        byte[] inputUtf8Bytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] encoded = new byte[2 + inputUtf8Bytes.length];
        encoded[0] = 0x0c;
        encoded[1] = (byte) inputUtf8Bytes.length;
        System.arraycopy(inputUtf8Bytes, 0, encoded, 2, inputUtf8Bytes.length);

        Asn1Utf8String utf8String = (Asn1Utf8String) Asn1.decode(encoded);
        assertThat(utf8String.encodingLength()).isEqualTo(encoded.length);
        assertThat(utf8String.encode()).isEqualTo(encoded);

        // Testing length >= 128
        input = "Википедия расположена на серверах Фонда Викимедиа "
                + "— некоммерческой организации, также обеспечивающей работу ряда других проектов";
        inputUtf8Bytes = input.getBytes(StandardCharsets.UTF_8);
        encoded = new byte[3 + inputUtf8Bytes.length];
        encoded[0] = 0x0c;
        encoded[1] = (byte) ((1 << 7) | 1);
        encoded[2] = (byte) inputUtf8Bytes.length;
        System.arraycopy(inputUtf8Bytes, 0, encoded, 3, inputUtf8Bytes.length);

        utf8String = (Asn1Utf8String) Asn1.decode(encoded);
        assertThat(utf8String.encodingLength()).isEqualTo(encoded.length);
        assertThat(utf8String.encode()).isEqualTo(encoded);
    }

}
