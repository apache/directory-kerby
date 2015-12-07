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

import org.apache.kerby.asn1.Asn1Header;
import org.apache.kerby.asn1.Tag;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class Asn1ParsingResult extends AbstractAsn1Type<Asn1Type> {
    protected Asn1Header header;

    public Asn1ParsingResult(Tag tag) {
        super(tag);
        setValue(this);
    }

    public Asn1ParsingResult(Asn1Header header) {
        super(header.getTag());
        setValue(this);
        this.header = header;
    }

    protected ByteBuffer getBodyBuffer() {
        return header.getBodyBuffer();
    }

    protected Asn1Header getHeader() {
        return header;
    }

    @Override
    protected int encodingBodyLength() {
        return header.getActualBodyLength();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        buffer.put(header.getBodyBuffer());
    }

    protected int getOffset() {
        return header.getBodyStart() - encodingHeaderLength();
    }

    @Override
    protected void decodeBody(Asn1Header header) throws IOException {
        // NOT USED FOR NOW SINCE WE DON'T DECODE THE BODY.
    }

    @Override
    public String toString() {
        String valueStr = "undecoded";
        if (getValue() != null) {
            Asn1Type val = getValue();
            valueStr = (val != null ? val.toString() : "null");
        }
        String typeStr = tag().isUniversal() ? tag().universalTag().toStr()
            : tag().tagClass().name().toLowerCase();
        return typeStr + " ["
            + "off=" + getOffset()
            + ", len=" + encodingHeaderLength() + "+" + encodingBodyLength()
            + "] "
            + valueStr;
    }
}
