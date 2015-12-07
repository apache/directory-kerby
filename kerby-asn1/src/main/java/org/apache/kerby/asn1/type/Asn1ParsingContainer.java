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
package org.apache.kerby.asn1.type;

import org.apache.kerby.asn1.Asn1Dumpable;
import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.Asn1Header;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.util.Asn1Reader;
import org.apache.kerby.asn1.util.Asn1Reader2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * ASN1 constructed types, mainly structured ones, but also some primitive ones.
 */
public class Asn1ParsingContainer
    extends Asn1ParsingResult implements Asn1Dumpable {

    private List<Asn1ParsingResult> parsingResults = new ArrayList<>();

    public Asn1ParsingContainer(Tag tag) {
        super(tag);
    }

    public Asn1ParsingContainer(Asn1Header header) {
        super(header);
        usePrimitive(false);
    }

    public List<Asn1ParsingResult> getParsingResults() {
        return parsingResults;
    }

    public void addItem(Asn1ParsingResult value) {
        parsingResults.add(value);
    }

    public void clear() {
        parsingResults.clear();
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        Asn1Reader2 reader = new Asn1Reader2(content);
        Asn1Header header = reader.readHeader();
        Tag tmpTag = header.getTag();
        useDefinitiveLength(header.isDefinitiveLength());

        if (!tag().equals(tmpTag)) {
            throw new IOException("Unexpected tag " + tmpTag
                + ", expecting " + tag());
        }

        decode(header);
    }

    @Override
    public void decode(Asn1Header header) throws IOException {
        this.header = header;

        Asn1Reader reader = new Asn1Reader2(header.getBuffer());
        int pos = header.getBodyStart();
        while (true) {
            reader.setPosition(pos);
            Asn1ParsingResult asn1Obj = decodeOne(reader);
            if (asn1Obj == null) {
                break;
            }

            pos += asn1Obj.encodingLength();
            if (asn1Obj.isEOC()) {
                break;
            }

            if (header.getBodyEnd() != -1 && pos >= header.getBodyEnd()) {
                break;
            }
        }

        header.setBodyEnd(pos);
    }

    private Asn1ParsingResult decodeOne(Asn1Reader reader) throws IOException {
        return decodeOne(reader, this);
    }

    public static Asn1ParsingResult decodeOne(ByteBuffer content) throws IOException {
        Asn1Reader reader = new Asn1Reader2(content);
        return Asn1ParsingContainer.decodeOne(reader, null);
    }

    public static Asn1ParsingResult decodeOne(Asn1Reader reader,
                                     Asn1ParsingContainer parent) throws IOException {
        if (!reader.available()) {
            return null;
        }

        Asn1Header header = reader.readHeader();
        Tag tmpTag = header.getTag();
        Asn1ParsingResult parsingResult;

        if (tmpTag.isPrimitive()) {
            parsingResult = new Asn1ParsingItem(header);
            parsingResult.useDefinitiveLength(header.isDefinitiveLength());
        } else {
            Asn1ParsingContainer container = new Asn1ParsingContainer(tmpTag);
            container.useDefinitiveLength(header.isDefinitiveLength());
            container.decode(header);
            parsingResult = container;
        }

        if (parsingResult != null && parent != null) {
            parent.addItem(parsingResult);
        }

        return parsingResult;
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        dumper.indent(indents).append(toString()).newLine();

        for (Asn1ParsingResult aObj : parsingResults) {
            dumper.dumpType(indents + 4, aObj).newLine();
        }
    }

    @Override
    public String toString() {
        String typeStr;
        if (tag().isUniversal()) {
            typeStr = tag().universalTag().toStr();
        } else if (tag().isAppSpecific()) {
            typeStr = "application " + tagNo();
        } else {
            typeStr = "[" + tagNo() + "]";
        }
        return typeStr + " ["
            + "off=" + getOffset()
            + ", len=" + encodingHeaderLength() + "+" + encodingBodyLength()
            + (isDefinitiveLength() ? "" : "(undefined)")
            + "]";
    }
}
