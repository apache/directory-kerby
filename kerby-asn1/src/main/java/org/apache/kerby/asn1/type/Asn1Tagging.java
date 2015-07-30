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

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;

/**
 * For tagging any Asn1Type with a tagNo
 */
public class Asn1Tagging<T extends Asn1Type> extends AbstractAsn1Type<T> {

    public Asn1Tagging(boolean isAppSpecific) {
        this(-1, null, isAppSpecific);
    }

    public Asn1Tagging(int tagNo, T value, boolean isAppSpecific) {
        super(isAppSpecific ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC, tagNo, value);
        getEncodingOption().useExplicit();
        if (value == null) {
            initValue();
        }
    }

    @Override
    protected int encodingBodyLength() {
        AbstractAsn1Type<?> value = (AbstractAsn1Type<?>) getValue();
        if (getEncodingOption().isExplicit()) {
            return value.encodingLength();
        } else if (getEncodingOption().isImplicit()) {
            return value.encodingBodyLength();
        } else {
            throw new RuntimeException("Invalid decoding option, "
                    + "only allowing explicit/implicit");
        }
    }

    @Override
    public boolean isConstructed() {
        if (getEncodingOption().isExplicit()) {
            return true;
        } else if (getEncodingOption().isImplicit()) {
            AbstractAsn1Type<?> value = (AbstractAsn1Type<?>) getValue();
            return value.isConstructed();
        }
        return false;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        AbstractAsn1Type<?> value = (AbstractAsn1Type<?>) getValue();
        if (getEncodingOption().isExplicit()) {
            value.encode(buffer);
        } else if (getEncodingOption().isImplicit()) {
            value.encodeBody(buffer);
        } else {
            throw new RuntimeException("Invalid decoding option, "
                    + "only allowing explicit/implicit");
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        AbstractAsn1Type<?> value = (AbstractAsn1Type<?>) getValue();
        if (getEncodingOption().isExplicit()) {
            value.decode(content);
        } else if (getEncodingOption().isImplicit()) {
            value.decodeBody(content);
        } else {
            throw new RuntimeException("Invalid decoding option, "
                    + "only allowing explicit/implicit");
        }
    }

    private void initValue() {
        Class<? extends Asn1Type> valueType = (Class<T>) ((ParameterizedType)
                getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        AbstractAsn1Type<?> value = null;
        try {
            value = (AbstractAsn1Type<?>) valueType.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create tagged value", e);
        }
        setValue((T) value);
    }
}
