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

import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1Dump {

    public static void dump(Asn1Type value) {
        Asn1Dumper dumper = new Asn1Dumper();
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
    }

    public static void dump(byte[] content) throws IOException {
        String hexStr = HexUtil.bytesToHex(content);
        System.out.println("Dumping data:");
        System.out.println(hexStr);
        Asn1Dumper dumper = new Asn1Dumper();
        dumper.dump(content);
    }

    public static void dump(ByteBuffer content) throws IOException {
        byte[] bytes = new byte[content.remaining()];
        content.get(bytes);
        dump(bytes);
    }
}
