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

import org.apache.kerby.asn1.Asn1Factory;
import org.apache.kerby.asn1.Asn1Header;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Asn1Item serves two purposes:
 * 1. Wrapping an existing Asn1Type value for Asn1Collection;
 * 2. Wrapping a half decoded value whose body content is left to be decoded
 * later when appropriate.
 * Why not fully decoded at once? Lazy and decode on demand for collection, or
 * impossible due to lacking key parameters, like implicit encoded value for
 * tagged value.
 *
 * For not fully decoded value, you tell your case using isSimple/isCollection/
 * isSpecific/isContextSpecific etc., then call decodeValueAsSimple/
 * decodeValueAsCollection/decodeValueAsImplicitTagged/decodeValueAsExplicitTagged etc.
 * to decode it fully. Or if you have already derived the value holder or
 * the holder type, you can use decodeValueWith or decodeValueAs with your
 * holder or hodler type.
 */
public class Asn1Item extends AbstractAsn1Type<Asn1Type> {
    private final Asn1ParsingResult parsingResult;

    public Asn1Item(Asn1ParsingResult parsingResult) {
        super(parsingResult.tag());
        this.parsingResult = parsingResult;
    }

    public Asn1Item(Tag tag, Asn1ParsingResult parsingResult) {
        super(tag);
        this.parsingResult = parsingResult;
    }

    public Asn1ParsingResult getParsingResult() {
        return parsingResult;
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() != null) {
            return ((AbstractAsn1Type<?>) getValue()).encodingBodyLength();
        }
        return parsingResult.encodingBodyLength();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        if (getValue() != null) {
            ((Asn1Object) getValue()).encodeBody(buffer);
        }
    }

    @Override
    protected void decodeBody(Asn1Header header) throws IOException {
        this.parsingResult.decodeBody(header);
    }

    public boolean isFullyDecoded() {
        return getValue() != null;
    }

    public void decodeValueAsSimple() throws IOException {
        if (getValue() != null) {
            return;
        }
        if (!isSimple()) {
            throw new IllegalArgumentException(
                "Attempting to decode non-simple value as simple");
        }

        Asn1Object value = (Asn1Object) Asn1Factory.create(tagNo());
        value.useDefinitiveLength(isDefinitiveLength());
        decodeValueWith(value);
    }

    public void decodeValueAsCollection() throws IOException {
        if (getValue() != null) {
            return;
        }
        if (!isCollection()) {
            throw new IllegalArgumentException(
                "Attempting to decode non-collection value as collection");
        }

        Asn1Type value = Asn1Factory.create(tagNo());
        value.useDefinitiveLength(isDefinitiveLength());
        decodeValueWith(value);
    }

    public void decodeValueAs(Class<? extends Asn1Type> type) throws IOException {
        Asn1Type value;
        try {
            value = type.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Invalid type: "
                + type.getCanonicalName(), e);
        }
        decodeValueWith(value);
    }

    public void decodeValueWith(Asn1Type value) throws IOException {
        setValue(value);
        value.useDefinitiveLength(isDefinitiveLength());
        ((Asn1Object) value).decode(parsingResult.getHeader());
    }

    public void decodeValueWith(Asn1Type value, TaggingOption taggingOption) throws IOException {
        if (!isTagSpecific()) {
            throw new IllegalArgumentException(
                "Attempting to decode non-tagged value using tagging way");
        }
        ((Asn1Object) value).taggedDecode(parsingResult.getHeader(), taggingOption);
        setValue(value);
    }
}
