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

import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.UniversalTag;
import org.apache.kerby.asn1.parse.Asn1Item;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * ASN1 simple type, of single value other than complex type of multiple values.
 */
public abstract class Asn1Simple<T> extends AbstractAsn1Type<T> {
    private byte[] bytes;

    /**
     * Default constructor, generally for decoding as a value container
     * @param tagNo The tag number
     */
    public Asn1Simple(UniversalTag tagNo) {
        this(tagNo, null);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param universalTag The tag number
     * @param value The value
     */
    public Asn1Simple(UniversalTag universalTag, T value) {
        super(universalTag, value);
        usePrimitive(true);
    }

    @Override
    public boolean isDefinitiveLength() {
        return true; // TO-BE-FIXED: some primitive types may not.
    }

    protected byte[] getBytes() {
        return bytes;
    }

    protected void setBytes(byte[] bytes) {
        resetBodyLength();
        this.bytes = bytes;
    }

    protected byte[] encodeBody() {
        if (bytes == null) {
            toBytes();
        }
        return bytes;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        byte[] body = encodeBody();
        if (body != null) {
            buffer.put(body);
        }
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() == null) {
            return 0;
        }
        if (bytes == null) {
            toBytes();
        }
        return bytes.length;
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        Asn1Item item = (Asn1Item) parseResult;
        byte[] leftBytes = item.readBodyBytes();
        if (leftBytes.length > 0) {
            setBytes(leftBytes);
            toValue();
        }
    }

    protected void toValue() throws IOException { }

    protected void toBytes() { }

    public static boolean isSimple(Tag tag) {
        return isSimple(tag.universalTag());
    }

    public static boolean isSimple(int tag) {
        return isSimple(new Tag(tag));
    }

    public static boolean isSimple(UniversalTag tagNo) {
        switch (tagNo) {
            case BIT_STRING:
            case BMP_STRING:
            case BOOLEAN:
            case ENUMERATED:
            case GENERALIZED_TIME:
            case GENERAL_STRING:
            case IA5_STRING:
            case INTEGER:
            case NULL:
            case NUMERIC_STRING:
            case OBJECT_IDENTIFIER:
            case OCTET_STRING:
            case PRINTABLE_STRING:
            case T61_STRING:
            case UNIVERSAL_STRING:
            case UTC_TIME:
            case UTF8_STRING:
            case VISIBLE_STRING:
                return true;
            default:
                return false;
        }
    }

    /**
     * Create a simple ASN1 object given tagNo, using the default constructor
     * with no value provided
     * @param tagNo The tag number
     * @return A simple ASN1 object
     */
    public static Asn1Simple<?> createSimple(int tagNo) {
        if (!isSimple(tagNo)) {
            throw new IllegalArgumentException("Not simple type, tag: " + tagNo);
        }
        return createSimple(UniversalTag.fromValue(tagNo));
    }

    /**
     * Create a simple ASN1 object given tagNo, using the default constructor
     * with no value provided
     * @param tagNo The tag number
     * @return The simple ASN1 object
     */
    public static Asn1Simple<?> createSimple(UniversalTag tagNo) {
        if (!isSimple(tagNo)) {
            throw new IllegalArgumentException("Not simple type, tag: " + tagNo);
        }

        switch (tagNo) {
            case BIT_STRING:
                return new Asn1BitString();
            case BMP_STRING:
                return new Asn1BmpString();
            case BOOLEAN:
                return new Asn1Boolean();
            case ENUMERATED:
                return null;
            case GENERALIZED_TIME:
                return new Asn1GeneralizedTime();
            case GENERAL_STRING:
                return new Asn1GeneralString();
            case IA5_STRING:
                return new Asn1IA5String();
            case INTEGER:
                return new Asn1Integer();
            case NULL:
                return Asn1Null.INSTANCE;
            case NUMERIC_STRING:
                return new Asn1NumericsString();
            case OBJECT_IDENTIFIER:
                return new Asn1ObjectIdentifier();
            case OCTET_STRING:
                return new Asn1OctetString();
            case PRINTABLE_STRING:
                return new Asn1PrintableString();
            case T61_STRING:
                return new Asn1T61String();
            case UNIVERSAL_STRING:
                return new Asn1UniversalString();
            case UTC_TIME:
                return new Asn1UtcTime();
            case UTF8_STRING:
                return new Asn1Utf8String();
            case VISIBLE_STRING:
                return new Asn1VisibleString();
            default:
                throw new IllegalArgumentException(
                    "Unexpected tag " + tagNo.getValue());
        }
    }

    @Override
    public String toString() {
        String typeStr = simpleInfo();
        T theValue = getValue();
        String valueStr = (theValue != null ? String.valueOf(theValue) : "null");
        return typeStr + valueStr;
    }
}
