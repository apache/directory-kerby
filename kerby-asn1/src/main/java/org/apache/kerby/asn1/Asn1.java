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

import org.apache.kerby.asn1.type.Asn1ParsingContainer;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.asn1.util.Asn1Reader1;
import org.apache.kerby.asn1.util.HexUtil;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The shortcut API for ASN1 encoding, decoding and dumping.
 * TO BE WELL DOCUMENTED.
 */
public final class Asn1 {

    private Asn1() {

    }

    public static void encode(ByteBuffer buffer, Asn1Type value) {
        value.encode(buffer);
    }

    public static byte[] encode(Asn1Type value) {
        return value.encode();
    }

    public static Asn1Header decodeHeader(ByteBuffer content) throws IOException {
        Asn1Reader1 reader = new Asn1Reader1(content);
        return reader.readHeader();
    }

    public static Asn1Type decode(byte[] content) throws IOException {
        return decode(ByteBuffer.wrap(content));
    }

    /*
    public static Asn1Type decode(ByteBuffer content) throws IOException {
        Asn1Reader1 reader = new Asn1Reader1(content);
        Asn1Header header = reader.readHeader();

        Asn1Item result = new Asn1Item(header.getTag(), header.getBuffer());
        result.useDefinitiveLength(header.isDefinitiveLength());

        return result;
    }*/

    public static Asn1Type decode(ByteBuffer content) throws IOException {
        return Asn1ParsingContainer.decodeOne(content);
    }

    public static void dump(Asn1Type value) {
        dump(value, true);
    }

    public static void dump(Asn1Type value, boolean withType) {
        Asn1Dumper dumper = new Asn1Dumper(withType);
        if (!withType) {
            dumper.dumpTypeInfo(value.getClass());
        }
        dumper.dumpType(0, value);
        String output = dumper.output();
        System.out.println(output);
    }

    public static void dump(String hexStr) throws IOException {
        System.out.println("Dumping data:");
        System.out.println(hexStr);
        Asn1Dumper dumper = new Asn1Dumper();
        byte[] data = HexUtil.hex2bytes(hexStr);
        dumper.dump(data);
        String output = dumper.output();
        System.out.println(output);
    }

    public static void dump(byte[] content) throws IOException {
        String hexStr = HexUtil.bytesToHex(content);
        System.out.println("Dumping data:");
        int range = 100;
        int pos = range;
        while (pos < hexStr.length()) {
            System.out.println(hexStr.substring(pos - range, pos));
            pos = pos + range;
        }
        System.out.println(hexStr.substring(pos - range, hexStr.length()));

        Asn1Dumper dumper = new Asn1Dumper();
        dumper.dump(content);
        String output = dumper.output();
        System.out.println(output);
    }

    public static void dump(ByteBuffer content) throws IOException {
        byte[] bytes = new byte[content.remaining()];
        content.get(bytes);
        dump(bytes);
    }
}
