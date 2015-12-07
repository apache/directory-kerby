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

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.Asn1Header;
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Can be any valid ASN-1 ojbect, limited or not limited.
 */
public class Asn1Any extends AbstractAsn1Type<Asn1Type> {
    private Asn1FieldInfo fieldInfo;
    private Asn1Item field;

    public Asn1Any() {
        super(UniversalTag.ANY);
    }

    public Asn1Any(Asn1Type anyValue) {
        this();
        setValue(anyValue);
    }

    public void setField(Asn1Item field) {
        this.field = field;
    }

    public void setFieldInfo(Asn1FieldInfo fieldInfo) {
        this.fieldInfo = fieldInfo;
    }

    public Asn1Type getField() {
        return field;
    }

    @Override
    protected int encodingBodyLength() {
        return ((Asn1Object) getValue()).encodingBodyLength();
    }

    @Override
    protected void decodeBody(Asn1Header header) throws IOException {
        ((Asn1Object) getValue()).decodeBody(header);
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        ((Asn1Object) getValue()).encodeBody(buffer);
    }

    protected <T extends Asn1Type> T getValueAs(Class<T> t) {
        Asn1Type value = getValue();
        if (value != null) {
            return (T) value;
        }

        T result;
        try {
            result = t.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("No default constructor?", e);
        }

        try {
            if (field.isContextSpecific()) {
                field.decodeValueWith(result,
                    fieldInfo.getTaggingOption());
            } else {
                field.decodeValueWith(result);
            }
        } catch (IOException e) {
            throw new RuntimeException("Fully decoding failed", e);
        }

        return result;
    }
}

