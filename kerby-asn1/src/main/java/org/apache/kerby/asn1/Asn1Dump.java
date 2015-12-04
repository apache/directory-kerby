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

import org.apache.kerby.asn1.type.Asn1Constructed;
import org.apache.kerby.asn1.type.Asn1Item;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1Dump {

    public static void dump(String hexStr) throws IOException {
        System.out.println("Dumping data:");
        System.out.println(hexStr);
        Asn1Dump dumper = new Asn1Dump();
        byte[] data = HexUtil.hex2bytes(hexStr);
        dumper.doDump(data);
    }

    public static void dump(byte[] content) throws IOException {
        String hexStr = HexUtil.bytesToHex(content);
        System.out.println("Dumping data:");
        System.out.println(hexStr);
        Asn1Dump dumper = new Asn1Dump();
        dumper.doDump(content);
    }

    public static void dump(ByteBuffer content) throws IOException {
        byte[] bytes = new byte[content.remaining()];
        content.get(bytes);
        dump(bytes);
    }

    private StringBuilder builder = new StringBuilder();

    private void doDump(byte[] content) throws IOException {
        doDump(ByteBuffer.wrap(content));
    }

    private void doDump(ByteBuffer content) throws IOException {
        Asn1InputBuffer buffer = new Asn1InputBuffer(content);
        Asn1Type value = buffer.read();
        if (value == null) {
            return;
        }

        dumpType(0, value);

        System.out.println(builder.toString());
    }

    private void dumpType(int numSpaces, Asn1Type value) {
        if (value instanceof Asn1Item) {
            dumpItem(numSpaces, (Asn1Item) value);
        } else if (value instanceof Asn1Constructed) {
            dumpCollection(numSpaces, (Asn1Constructed) value);
        }
    }

    private void dumpCollection(int numSpaces, Asn1Constructed coll) {
        prefixSpaces(numSpaces).append(coll).append("\n");
        for (Asn1Type aObj : coll.getValue()) {
            dumpType(numSpaces + 4, aObj);
        }
    }

    private void dumpItem(int numSpaces, Asn1Item value) {
        prefixSpaces(numSpaces).append(value).append("\n");
    }

    private StringBuilder prefixSpaces(int numSpaces) {
        for (int i = 0; i < numSpaces; i++) {
            builder.append(' ');
        }
        return builder;
    }
}
