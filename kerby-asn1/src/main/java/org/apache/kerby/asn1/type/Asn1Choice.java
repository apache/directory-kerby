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
import org.apache.kerby.asn1.Asn1Dumpable;
import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.TaggingOption;
import org.apache.kerby.asn1.UniversalTag;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1Choice
    extends AbstractAsn1Type<Asn1Type> implements Asn1Dumpable {

    private final Asn1FieldInfo[] fieldInfos;
    private final Tag[] tags;

    private Asn1FieldInfo chosenField;

    public Asn1Choice(Asn1FieldInfo[] fieldInfos) {
        super(UniversalTag.CHOICE);

        this.fieldInfos = fieldInfos;
        this.tags = new Tag[fieldInfos.length];
        initTags();
    }

    @Override
    public Tag tag() {
        if (getValue() != null) {
            return getValue().tag();
        } else if (chosenField != null) {
            return chosenField.getFieldTag();
        }
        return super.tag();
    }

    private void initTags() {
        for (int i = 0; i < fieldInfos.length; i++) {
            tags[i] = fieldInfos[i].getFieldTag();
        }
    }

    public boolean matchAndSetValue(Tag tag) {
        int foundPos = -1;
        for (int i = 0; i < fieldInfos.length; i++) {
            if (tag.isContextSpecific()) {
                if (fieldInfos[i].getTagNo() == tag.tagNo()) {
                    foundPos = i;
                    break;
                }
            } else if (tags[i].equals(tag)) {
                foundPos = i;
                break;
            }
        }

        if (foundPos != -1) {
            this.chosenField = fieldInfos[foundPos];
            setValue(fieldInfos[foundPos].createFieldValue());
            return true;
        }
        return false;
    }

    @Override
    public byte[] encode() throws IOException {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (chosenField.isTagged()) {
                TaggingOption taggingOption =
                        chosenField.getTaggingOption();
                return theValue.taggedEncode(taggingOption);
            } else {
                return theValue.encode();
            }
        }
        return null;
    }

    @Override
    public void encode(ByteBuffer buffer) throws IOException {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (chosenField.isTagged()) {
                TaggingOption taggingOption =
                        chosenField.getTaggingOption();
                theValue.taggedEncode(buffer, taggingOption);
            } else {
                theValue.encode(buffer);
            }
        }
    }

    @Override
    public int encodingLength() {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (chosenField.isTagged()) {
                TaggingOption taggingOption =
                    chosenField.getTaggingOption();
                return theValue.taggedEncodingLength(taggingOption);
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
    protected void encodeBody(ByteBuffer buffer) throws IOException {
        Asn1Encodeable theValue = (Asn1Encodeable) getValue();

        if (theValue != null) {
            if (chosenField.isTagged()) {
                TaggingOption taggingOption =
                    chosenField.getTaggingOption();
                theValue.taggedEncode(buffer, taggingOption);
            } else {
                theValue.encode(buffer);
            }
        }
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        chosenField = null;
        setValue(null);

        super.decode(content);
    }

    @Override
    public void decode(Asn1ParseResult parseResult) throws IOException {
        if (chosenField == null) {
            matchAndSetValue(parseResult.tag());
        }

        decodeBody(parseResult);
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        if (chosenField == null) {
            matchAndSetValue(parseResult.tag());
        }

        if (chosenField == null) {
            throw new IOException("Unexpected item, not in choices: "
                + parseResult.simpleInfo());
        }

        Asn1Type fieldValue = getValue();
        if (parseResult.isContextSpecific()) {
            Asn1Binder.bindWithTagging(parseResult, fieldValue,
                chosenField.getTaggingOption());
        } else {
            Asn1Binder.bind(parseResult, fieldValue);
        }
    }

    protected <T extends Asn1Type> T getChoiceValueAs(EnumType index, Class<T> t) {
        if (chosenField == null || getValue() == null) {
            return null;
        }

        if (chosenField != null && index != chosenField.getIndex()) {
            throw new IllegalArgumentException("Incorrect chosen value requested");
        }

        return (T) getValue();
    }

    protected void setChoiceValue(EnumType index, Asn1Type value) {
        if (fieldInfos[index.getValue()].getIndex() != index) {
            throw new IllegalArgumentException("Incorrect choice option to set");
        }

        this.chosenField = fieldInfos[index.getValue()];
        setValue(value);
    }

    protected void setChoiceValueAsOctets(EnumType index, byte[] bytes) {
        Asn1OctetString value = new Asn1OctetString(bytes);
        setChoiceValue(index, value);
    }

    protected byte[] getChoiceValueAsOctets(EnumType index) {
        Asn1OctetString value = getChoiceValueAs(index, Asn1OctetString.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        Asn1Type theValue = getValue();
        dumper.indent(indents).append("<Choice>").newLine();
        //dumper.append(simpleInfo()).newLine();
        dumper.dumpType(indents, theValue);
    }
}
