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
package org.apache.kerby.asn1.parse;

import org.apache.kerby.asn1.Tag;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * ASN1 parser.
 */
public class Asn1Parser {

    public static void parse(Asn1Container container) throws IOException {
        Asn1Reader reader = new Asn1Reader(container.getBuffer());
        int pos = container.getBodyStart();
        while (true) {
            reader.setPosition(pos);
            Asn1ParseResult asn1Obj = parse(reader);
            if (asn1Obj == null) {
                break;
            }

            container.addItem(asn1Obj);

            pos += asn1Obj.getEncodingLength();
            if (asn1Obj.isEOC()) {
                break;
            }

            if (container.checkBodyFinished(pos)) {
                break;
            }
        }

        container.setBodyEnd(pos);
    }

    public static Asn1ParseResult parse(ByteBuffer content) throws IOException {
        Asn1Reader reader = new Asn1Reader(content);
        return parse(reader);
    }

    public static Asn1ParseResult parse(Asn1Reader reader) throws IOException {
        if (!reader.available()) {
            return null;
        }

        Asn1Header header = reader.readHeader();
        Tag tmpTag = header.getTag();
        int bodyStart = reader.getPosition();
        Asn1ParseResult parseResult;

        if (tmpTag.isPrimitive()) {
            parseResult = new Asn1Item(header, bodyStart, reader.getBuffer());
        } else {
            Asn1Container container = new Asn1Container(header,
                bodyStart, reader.getBuffer());
            if (header.getLength() != 0) {
                parse(container);
            }
            parseResult = container;
        }

        return parseResult;
    }
}
