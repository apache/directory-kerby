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

import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1Type;
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

    public static void encode(ByteBuffer buffer, Asn1Type value) throws IOException {
        value.encode(buffer);
    }

    public static byte[] encode(Asn1Type value) throws IOException {
        return value.encode();
    }

    public static Asn1Type decode(byte[] content) throws IOException {
        return decode(ByteBuffer.wrap(content));
    }

    public static Asn1Type decode(ByteBuffer content) throws IOException {
        Asn1ParseResult parseResult = Asn1Parser.parse(content);
        return Asn1Converter.convert(parseResult, false);
    }

    public static Asn1ParseResult parse(byte[] content) throws IOException {
        return parse(ByteBuffer.wrap(content));
    }

    public static Asn1ParseResult parse(ByteBuffer content) throws IOException {
        return Asn1Parser.parse(content);
    }

    public static void dump(Asn1Type value) {
        Asn1Dumper dumper = new Asn1Dumper();
        dumper.dumpType(0, value);
        String output = dumper.output();
        System.out.println(output);
    }

    public static void parseAndDump(String hexStr) throws IOException {
        byte[] data = HexUtil.hex2bytes(hexStr);
        parseAndDump(data);
    }

    public static void decodeAndDump(String hexStr) throws IOException {
        byte[] data = HexUtil.hex2bytes(hexStr);
        decodeAndDump(data);
    }

    public static void parseAndDump(ByteBuffer content) throws IOException {
        byte[] bytes = new byte[content.remaining()];
        content.get(bytes);
        parseAndDump(bytes);
    }

    public static void decodeAndDump(ByteBuffer content) throws IOException {
        byte[] bytes = new byte[content.remaining()];
        content.get(bytes);
        decodeAndDump(bytes);
    }

    public static void parseAndDump(byte[] content) throws IOException {
        String hexStr = HexUtil.bytesToHex(content);
        Asn1Dumper dumper = new Asn1Dumper();
        System.out.println("Dumping data:");
        dumper.dumpData(hexStr);
        dumper.parseAndDump(content);
        String output = dumper.output();
        System.out.println(output);
    }

    public static void decodeAndDump(byte[] content) throws IOException {
        String hexStr = HexUtil.bytesToHex(content);
        Asn1Dumper dumper = new Asn1Dumper();
        System.out.println("Dumping data:");
        dumper.dumpData(hexStr);
        dumper.decodeAndDump(content);
        String output = dumper.output();
        System.out.println(output);
    }
}
