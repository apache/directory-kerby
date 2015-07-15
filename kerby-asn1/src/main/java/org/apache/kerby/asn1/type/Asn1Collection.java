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

import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.TagClass;
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * ASN1 complex type, may be better named.
 */
public class Asn1Collection extends AbstractAsn1Type<List<Asn1Item>> {
    public Asn1Collection(TagClass tagClass, int tagNo) {
        super(tagClass, tagNo);
        setValue(new ArrayList<Asn1Item>());
        getEncodingOption().useConstructed();
    }

    @Override
    public boolean isConstructed() {
        return true;
    }

    public void addItem(Asn1Type value) {
        if (value instanceof Asn1Item) {
            getValue().add((Asn1Item) value);
        } else {
            getValue().add(new Asn1Item(value));
        }
    }

    public void clear() {
        getValue().clear();
    }

    @Override
    protected int encodingBodyLength() {
        List<Asn1Item> valueItems = getValue();
        int allLen = 0;
        for (Asn1Item item : valueItems) {
            if (item != null) {
                allLen += item.encodingLength();
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        List<Asn1Item> valueItems = getValue();
        for (Asn1Item item : valueItems) {
            if (item != null) {
                item.encode(buffer);
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        while (content.available()) {
            Asn1Type aValue = decodeOne(content);
            if (aValue != null) {
                addItem(aValue);
            } else {
                throw new RuntimeException("Unexpected running into here");
            }
        }
    }

    public static boolean isCollection(int tagNo) {
        return isCollection(UniversalTag.fromValue(tagNo));
    }

    public static boolean isCollection(UniversalTag tagNo) {
        switch (tagNo) {
            case SEQUENCE:
            case SEQUENCE_OF:
            case SET:
            case SET_OF:
                return true;
            default:
                return false;
        }
    }

    public static Asn1Type createCollection(int tagNo) {
        if (!isCollection(tagNo)) {
            throw new IllegalArgumentException("Not collection type, tag: " + tagNo);
        }
        return createCollection(UniversalTag.fromValue(tagNo));
    }

    public static Asn1Type createCollection(UniversalTag tagNo) {
        if (!isCollection(tagNo)) {
            throw new IllegalArgumentException("Not collection type, tag: " + tagNo);
        }

        switch (tagNo) {
            case SEQUENCE:
                return new Asn1Sequence();
            case SEQUENCE_OF:
                return new Asn1Sequence();
            case SET:
                return new Asn1Set();
            case SET_OF:
                return new Asn1Set();
            default:
                throw new IllegalArgumentException("Unexpected tag " + tagNo.getValue());
        }
    }

}
