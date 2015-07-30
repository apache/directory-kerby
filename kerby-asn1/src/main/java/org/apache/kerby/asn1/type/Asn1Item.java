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
import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Asn1Item serves two purposes:
 * 1. Wrapping an existing Asn1Type value for Asn1Collection;
 * 2. Wrapping a half decoded value whose body content is left to be decoded later when appropriate.
 * Why not fully decoded at once? Lazy and decode on demand for collection, or impossible due to lacking
 * key parameters, like implicit encoded value for tagged value.
 *
 * For not fully decoded value, you tell your case using isSimple/isCollection/isTagged/isContextSpecific etc.,
 * then call decodeValueAsSimple/decodeValueAsCollection/decodeValueAsImplicitTagged/decodeValueAsExplicitTagged etc.
 * to decode it fully. Or if you have already derived the value holder or the holder type, you can use decodeValueWith
 * or decodeValueAs with your holder or hodler type.
 */
public class Asn1Item extends AbstractAsn1Type<Asn1Type> {
    private LimitedByteBuffer bodyContent;

    public Asn1Item(Asn1Type value) {
        super(value.tagFlags(), value.tagNo(), value);
    }

    public Asn1Item(int tag, int tagNo, LimitedByteBuffer bodyContent) {
        super(tag, tagNo);
        this.bodyContent = bodyContent;
    }

    public LimitedByteBuffer getBodyContent() {
        return bodyContent;
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() != null) {
            return ((AbstractAsn1Type<?>) getValue()).encodingBodyLength();
        }
        return (int) bodyContent.hasLeft();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        if (getValue() != null) {
            ((AbstractAsn1Type<?>) getValue()).encodeBody(buffer);
        } else {
            try {
                buffer.put(bodyContent.readAllLeftBytes());
            } catch (IOException e) {
                throw new RuntimeException("Failed to read all left bytes from body content", e);
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer bodyContent) throws IOException {
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
            throw new IllegalArgumentException("Attempting to decode non-simple value as simple");
        }

        Asn1Type value = Asn1Factory.create(tagNo());
        decodeValueWith(value);
    }

    public void decodeValueAsCollection() throws IOException {
        if (getValue() != null) {
            return;
        }
        if (!isCollection()) {
            throw new IllegalArgumentException("Attempting to decode non-collection value as collection");
        }

        Asn1Type value = Asn1Factory.create(tagNo());
        decodeValueWith(value);
    }

    public void decodeValueAs(Class<? extends Asn1Type> type) throws IOException {
        Asn1Type value;
        try {
            value = type.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Invalid type: " + type.getCanonicalName(), e);
        }
        decodeValueWith(value);
    }

    public void decodeValueWith(Asn1Type value) throws IOException {
        setValue(value);
        ((AbstractAsn1Type<?>) value).decode(tagFlags(), tagNo(), bodyContent);
    }

    public void decodeValueAsImplicitTagged(int originalTag, int originalTagNo) throws IOException {
        if (!isTagged()) {
            throw new IllegalArgumentException("Attempting to decode non-tagged value using tagging way");
        }
        Asn1Item taggedValue = new Asn1Item(originalTag, originalTagNo, getBodyContent());
        decodeValueWith(taggedValue);
    }

    public void decodeValueAsExplicitTagged() throws IOException {
        if (!isTagged()) {
            throw new IllegalArgumentException("Attempting to decode non-tagged value using tagging way");
        }
        Asn1Item taggedValue = decodeOne(getBodyContent());
        decodeValueWith(taggedValue);
    }

    private void decodeValueWith(Asn1Item taggedValue) throws IOException {
        taggedValue.decodeValueAsSimple();
        if (taggedValue.isFullyDecoded()) {
            setValue(taggedValue.getValue());
        } else {
            setValue(taggedValue);
        }
    }

    public void decodeValueWith(Asn1Type value, TaggingOption taggingOption) throws IOException {
        if (!isTagged()) {
            throw new IllegalArgumentException("Attempting to decode non-tagged value using tagging way");
        }
        ((AbstractAsn1Type<?>) value).taggedDecode(tagFlags(), tagNo(), getBodyContent(), taggingOption);
        setValue(value);
    }
}
