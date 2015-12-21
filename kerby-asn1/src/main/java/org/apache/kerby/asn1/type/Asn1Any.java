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
import org.apache.kerby.asn1.Asn1Converter;
import org.apache.kerby.asn1.Asn1Dumpable;
import org.apache.kerby.asn1.Asn1Dumper;
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
public class Asn1Any
    extends AbstractAsn1Type<Asn1Type> implements Asn1Dumpable {
    private Class<? extends Asn1Type> valueType;
    private Asn1FieldInfo decodeInfo;
    private Asn1ParseResult parseResult;
    private boolean isBlindlyDecoded = true;

    public Asn1Any() {
        super(UniversalTag.ANY);
    }

    public Asn1Any(Asn1Type anyValue) {
        this();
        setValue(anyValue);
    }

    @Override
    public Tag tag() {
        if (getValue() != null) {
            return getValue().tag();
        } else if (parseResult != null) {
            return parseResult.tag();
        }
        return super.tag();
    }

    public void setValueType(Class<? extends Asn1Type> valueType) {
        this.valueType = valueType;
    }

    public void setDecodeInfo(Asn1FieldInfo decodeInfo) {
        this.decodeInfo = decodeInfo;
    }

    public Asn1ParseResult getParseResult() {
        return parseResult;
    }

    @Override
    public void encode(ByteBuffer buffer) throws IOException {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (!isBlindlyDecoded) {
                if (decodeInfo.isTagged()) {
                    TaggingOption taggingOption =
                        decodeInfo.getTaggingOption();
                    theValue.taggedEncode(buffer, taggingOption);
                } else {
                    theValue.encode(buffer);
                }
            } else {
                theValue.encode(buffer);
            }
        }
    }

    @Override
    public int encodingLength() {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (!isBlindlyDecoded) {
                if (decodeInfo.isTagged()) {
                    TaggingOption taggingOption =
                        decodeInfo.getTaggingOption();
                    return theValue.taggedEncodingLength(taggingOption);
                } else {
                    return theValue.encodingLength();
                }
            } else {
                return theValue.encodingLength();
            }
        }

        return super.encodingLength();
    }

    @Override
    protected int encodingBodyLength() {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue == null) {
            return 0;
        }

        return -1; // Indicate error, shouldn't be here.
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        setValue(null);

        super.decode(content);
    }

    @Override
    public void decode(Asn1ParseResult parseResult) throws IOException {
        // Avoid the tag checking here.
        decodeBody(parseResult);
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        this.parseResult = parseResult;

        if (valueType != null) {
            typeAwareDecode(valueType);
        } else {
            blindlyDecode();
        }
    }

    private void blindlyDecode() throws IOException {
        Asn1Type anyValue = Asn1Converter.convert(parseResult, false);
        if (decodeInfo != null && decodeInfo.isTagged()) {
            // Escape the wrapper
            Asn1Constructed constructed = (Asn1Constructed) anyValue;
            Asn1Type innerValue = constructed.getValue().get(0);
            setValue(innerValue);
        } else {
            setValue(anyValue);
        }

        isBlindlyDecoded = true;
    }

    protected <T extends Asn1Type> T getValueAs(Class<T> t) {
        Asn1Type value = getValue();
        if (value != null && !isBlindlyDecoded) {
            return (T) value;
        }

        if (valueType != null && valueType != t) {
            throw new RuntimeException("Required value type isn't the same"
            + " with the value type set before");
        }

        try {
            typeAwareDecode(t);
        } catch (IOException e) {
            throw new RuntimeException("Type aware decoding of Any type failed");
        }

        return (T) getValue();
    }

    private <T extends Asn1Type> void typeAwareDecode(Class<T> t) throws IOException {
        T result;
        try {
            result = t.newInstance();
        } catch (Exception e) {
            throw new IOException("No default constructor?", e);
        }

        if (parseResult.isContextSpecific()) {
            Asn1Binder.bindWithTagging(parseResult, result,
                decodeInfo.getTaggingOption());
        } else {
            Asn1Binder.bind(parseResult, result);
        }

        setValue(result);
        isBlindlyDecoded = false;
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        Asn1Type theValue = getValue();
        dumper.indent(indents).append("<Any>").newLine();
        //dumper.append(simpleInfo()).newLine();
        dumper.dumpType(indents, theValue);
    }
}

