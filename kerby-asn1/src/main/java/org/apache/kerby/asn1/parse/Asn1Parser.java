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
        parse(container.header, container);
    }

    public static void parse(Asn1Header header,
                      Asn1Container parent) throws IOException {
        Asn1Reader reader = new Asn1Reader(header.getBuffer());
        int pos = header.getBodyStart();
        while (true) {
            reader.setPosition(pos);
            Asn1ParsingResult asn1Obj = parse(reader);
            if (asn1Obj == null) {
                break;
            }

            if (parent != null) {
                parent.addItem(asn1Obj);
            }

            pos += asn1Obj.getAllLength();
            if (asn1Obj.isEOC()) {
                break;
            }

            if (header.checkBodyFinished(pos)) {
                break;
            }
        }

        header.setBodyEnd(pos);
    }

    public static Asn1ParsingResult parse(ByteBuffer content) throws IOException {
        Asn1Reader reader = new Asn1Reader(content);
        return parse(reader);
    }

    public static Asn1ParsingResult parse(Asn1Reader reader) throws IOException {
        if (!reader.available()) {
            return null;
        }

        Asn1Header header = reader.readHeader();
        Tag tmpTag = header.getTag();
        Asn1ParsingResult parsingResult;

        if (tmpTag.isPrimitive()) {
            parsingResult = new Asn1Item(header);
        } else {
            Asn1Container container = new Asn1Container(header);
            parse(container);
            parsingResult = container;
        }

        return parsingResult;
    }
}
