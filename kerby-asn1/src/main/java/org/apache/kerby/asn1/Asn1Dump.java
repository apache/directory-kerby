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

import org.apache.kerby.asn1.type.Asn1Item;
import org.apache.kerby.asn1.type.Asn1Simple;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;

public class Asn1Dump {

    public static void dump(byte[] content) throws IOException {
        String dumped = dumpAsString(content);
        System.out.println(dumped);
    }

    public static String dumpAsString(byte[] content) throws IOException {
        StringBuilder sb = new StringBuilder();

        Asn1InputBuffer buffer = new Asn1InputBuffer(content);
        Asn1Type value;
        while (true) {
            value = buffer.read();
            if (value == null) {
                break;
            }
            dump(value, sb);
        }

        return sb.toString();
    }

    public static String dumpAsString(Asn1Type value) {
        StringBuilder sb = new StringBuilder();
        dump(value, sb);
        return sb.toString();
    }

    private static void dump(Asn1Type value, StringBuilder buffer) {
        if (value instanceof Asn1Simple) {
            buffer.append(((Asn1Simple<?>) value).getValue().toString());
        } else if (value instanceof Asn1Item) {
            dump((Asn1Item) value, buffer);
        }
    }

    private static void dump(Asn1Item value, StringBuilder buffer) {
        if (value.isFullyDecoded()) {
            dump(value.getValue(), buffer);
        } else {
            buffer.append("Asn1Item");
        }
    }
}
