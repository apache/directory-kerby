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

import org.apache.kerby.asn1.Asn1Binder;
import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.TaggingOption;
import org.apache.kerby.asn1.UniversalTag;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Can be any valid ASN-1 ojbect, limited or not limited.
 */
public class Asn1Any extends AbstractAsn1Type<Asn1Type> {
    private Asn1FieldInfo fieldInfo;
    private Asn1ParseResult field;

    public Asn1Any() {
        super(UniversalTag.ANY);
    }

    public Asn1Any(Asn1Type anyValue) {
        this();
        setValue(anyValue);
    }

    public void setFieldInfo(Asn1FieldInfo fieldInfo) {
        this.fieldInfo = fieldInfo;
    }

    public Asn1ParseResult getField() {
        return field;
    }

    @Override
    public Tag tag() {
        if (getValue() != null) {
            return getValue().tag();
        } else if (field != null) {
            return field.tag();
        }
        return super.tag();
    }

    @Override
    public void encode(ByteBuffer buffer) {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (fieldInfo.isTagged()) {
                TaggingOption taggingOption =
                        fieldInfo.getTaggingOption();
                theValue.taggedEncode(buffer, taggingOption);
            } else {
                theValue.encode(buffer);
            }
        }
    }

    @Override
    protected int encodingBodyLength() {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (fieldInfo.isTagged()) {
                TaggingOption taggingOption =
                    fieldInfo.getTaggingOption();
                return theValue.taggedEncodingLength(taggingOption);
            } else {
                return theValue.encodingLength();
            }
        }

        return 0; //field.getBodyLength();
    }

    @Override
    public void decode(Asn1ParseResult parseResult) throws IOException {
        // Avoid the tag checking here.
        decodeBody(parseResult);
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        this.field = parseResult;
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
                Asn1Binder.bindWithTagging(field, result,
                    fieldInfo.getTaggingOption());
            } else {
                Asn1Binder.bind(field, result);
            }
        } catch (IOException e) {
            throw new RuntimeException("Fully decoding failed", e);
        }

        return result;
    }
}

