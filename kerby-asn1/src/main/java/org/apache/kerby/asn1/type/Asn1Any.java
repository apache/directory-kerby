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

/**
 * Can be any valid ASN-1 ojbect, limited or not limited.
 *
 * WARNING!!!!
 * Note, this is far from complete, as most of parent methods are to override.
 */
public class Asn1Any extends AbstractAsn1Type<Asn1Type> {
    private Asn1Type field;

    public Asn1Any() {
        super(TagClass.UNIVERSAL, UniversalTag.ANY.getValue());
    }

    // For encoding phase.
    public Asn1Any(Asn1Type anyValue) {
        this();
        setValue(anyValue);
    }

    // For decoding phase, value may be an Asn1Item, not fully decoded.
    public void setItem(Asn1Type value) {
        this.field = value;
    }

    // For decoding phase.
    public Asn1Type getItem() {
        return field;
    }

    @Override
    protected int encodingBodyLength() {
        return ((AbstractAsn1Type<?>) getValue()).encodingBodyLength();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        ((AbstractAsn1Type<?>) getValue()).encodeBody(buffer);
    }

    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        // Not used
    }

    // Available for encoding phase.
    protected <T extends Asn1Type> T getValueAs(Class<T> t) {
        Asn1Type value = getValue();
        if (value == null) {
            return null;
        }
        return (T) value;
    }
}
