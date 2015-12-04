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
 * isTagged/isContextSpecific etc., then call decodeValueAsSimple/
 * decodeValueAsCollection/decodeValueAsImplicitTagged/decodeValueAsExplicitTagged etc.
 * to decode it fully. Or if you have already derived the value holder or
 * the holder type, you can use decodeValueWith or decodeValueAs with your
 * holder or hodler type.
 */
public class Asn1Item extends AbstractAsn1Type<Asn1Type> {
    private ByteBuffer bodyContent;

    public Asn1Item(Asn1Type value) {
        super(value.tag(), value);
    }

    public Asn1Item(Tag tag) {
        super(tag);
    }

    public Asn1Item(Tag tag, ByteBuffer bodyContent) {
        super(tag);
        this.bodyContent = bodyContent;
    }

    public void setBodyContent(ByteBuffer bodyContent) {
        this.bodyContent = bodyContent;
    }

    public ByteBuffer getBodyContent() {
        return bodyContent;
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() != null) {
            return ((AbstractAsn1Type<?>) getValue()).encodingBodyLength();
        }
        return (int) bodyContent.remaining();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        if (getValue() != null) {
            ((Asn1Object) getValue()).encodeBody(buffer);
        }
    }

    @Override
    protected void decodeBody(ByteBuffer bodyContent) throws IOException {
        this.bodyContent = bodyContent;
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
        ((AbstractAsn1Type<?>) value).decode(tag(), bodyContent);
    }

    public void decodeValueWith(Asn1Type value, TaggingOption taggingOption) throws IOException {
        if (!isTagged()) {
            throw new IllegalArgumentException(
                "Attempting to decode non-tagged value using tagging way");
        }
        ((Asn1Object) value).taggedDecode(tag(), getBodyContent(), taggingOption);
        setValue(value);
    }

    @Override
    public String toStr() {
        if (getValue() != null) {
            return getValue().toStr();
        }
        return "undecoded";
    }
}
