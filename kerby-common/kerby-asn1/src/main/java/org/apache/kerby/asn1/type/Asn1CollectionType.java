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
import org.apache.kerby.asn1.TaggingOption;
import org.apache.kerby.asn1.UniversalTag;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * For collection type that may consist of tagged fields
 */
public abstract class Asn1CollectionType
    extends AbstractAsn1Type<Asn1CollectionType> implements Asn1Dumpable {
    private final Asn1FieldInfo[] fieldInfos;
    private final Asn1Type[] fields;

    public Asn1CollectionType(UniversalTag universalTag,
                              final Asn1FieldInfo[] fieldInfos) {
        super(universalTag);

        setValue(this);
        this.fieldInfos = fieldInfos;
        this.fields = new Asn1Type[fieldInfos.length];
        usePrimitive(false);
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        int allLen = 0;
        int fieldLen;
        for (int i = 0; i < fields.length; ++i) {
            Asn1Encodeable field = (Asn1Encodeable) fields[i];
            if (field != null) {
                if (fieldInfos[i].isTagged()) {
                    TaggingOption taggingOption =
                        fieldInfos[i].getTaggingOption();
                    fieldLen = field.taggedEncodingLength(taggingOption);
                } else {
                    fieldLen = field.encodingLength();
                }
                allLen += fieldLen;
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) throws IOException {
        for (int i = 0; i < fields.length; ++i) {
            Asn1Type field = fields[i];
            if (field != null) {
                if (fieldInfos[i].isTagged()) {
                    TaggingOption taggingOption =
                        fieldInfos[i].getTaggingOption();
                    field.taggedEncode(buffer, taggingOption);
                } else {
                    field.encode(buffer);
                }
            }
        }
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        useDefinitiveLength(parseResult.isDefinitiveLength());

        Asn1Container container = (Asn1Container) parseResult;
        List<Asn1ParseResult> parseResults = container.getChildren();

        int lastPos = -1, foundPos = -1;

        for (Asn1ParseResult parseItem : parseResults) {
            if (parseItem.isEOC()) {
                continue;
            }

            foundPos = match(lastPos, parseItem);
            if (foundPos == -1) {
                throw new IOException("Unexpected item: " + parseItem.simpleInfo());
            }
            lastPos = foundPos;

            attemptBinding(parseItem, foundPos);
        }
    }

    private void attemptBinding(Asn1ParseResult parseItem,
                                int foundPos) throws IOException {
        Asn1FieldInfo fieldInfo = fieldInfos[foundPos];
        checkAndInitField(foundPos);
        Asn1Type fieldValue = fields[foundPos];

        if (fieldValue instanceof Asn1Any) {
            Asn1Any any = (Asn1Any) fieldValue;
            any.setDecodeInfo(fieldInfo);
            Asn1Binder.bind(parseItem, any);
        } else {
            if (parseItem.isContextSpecific()) {
                Asn1Binder.bindWithTagging(parseItem, fieldValue,
                    fieldInfo.getTaggingOption());
            } else {
                Asn1Binder.bind(parseItem, fieldValue);
            }
        }
    }

    private int match(int lastPos, Asn1ParseResult parseItem) {
        int foundPos = -1;
        for (int i = lastPos + 1; i < fieldInfos.length; ++i) {
            Asn1Type fieldValue = fields[i];
            Asn1FieldInfo fieldInfo = fieldInfos[i];

            if (fieldInfo.isTagged()) {
                if (!parseItem.isContextSpecific()) {
                    continue;
                }
                if (fieldInfo.getTagNo() == parseItem.tagNo()) {
                    foundPos = i;
                    break;
                }
            } else if (fieldValue != null) {
                if (fieldValue.tag().equals(parseItem.tag())) {
                    foundPos = i;
                    break;
                } else if (fieldValue instanceof Asn1Choice) {
                    Asn1Choice aChoice = (Asn1Choice) fieldValue;
                    if (aChoice.matchAndSetValue(parseItem.tag())) {
                        foundPos = i;
                        break;
                    }
                } else if (fieldValue instanceof Asn1Any) {
                    foundPos = i;
                    break;
                }
            } else {
                if (fieldInfo.getFieldTag().equals(parseItem.tag())) {
                    foundPos = i;
                    break;

                } else if (Asn1Choice.class
                        .isAssignableFrom(fieldInfo.getType())) {
                    Asn1Choice aChoice = (Asn1Choice) (fields[i] = fieldInfo
                            .createFieldValue());
                    if (aChoice.matchAndSetValue(parseItem.tag())) {
                        foundPos = i;
                        break;
                    }
                } else if (Asn1Any.class
                        .isAssignableFrom(fieldInfo.getType())) {
                    foundPos = i;
                    break;
                }
            }
        }

        return foundPos;
    }

    private void checkAndInitField(int index) {
        if (fields[index] == null) {
            fields[index] = fieldInfos[index].createFieldValue();
        }
    }

    protected abstract Asn1Collection createCollection();

    @SuppressWarnings("unchecked")
    protected <T extends Asn1Type> T getFieldAs(EnumType index, Class<T> t) {
        Asn1Type value = fields[index.getValue()];
        if (value == null) {
            return null;
        }
        return (T) value;
    }

    protected void setFieldAs(EnumType index, Asn1Type value) {
        resetBodyLength(); // Reset the pre-computed body length
        if (value instanceof Asn1Encodeable) {
            ((Asn1Encodeable) value).outerEncodeable = this;
        }
        fields[index.getValue()] = value;
    }

    protected String getFieldAsString(EnumType index) {
        Asn1Type value = fields[index.getValue()];
        if (value == null) {
            return null;
        }

        if (value instanceof Asn1String) {
            return ((Asn1String) value).getValue();
        }

        throw new RuntimeException("The targeted field type isn't of string");
    }

    protected byte[] getFieldAsOctets(EnumType index) {
        Asn1OctetString value = getFieldAs(index, Asn1OctetString.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    protected void setFieldAsOctets(EnumType index, byte[] bytes) {
        Asn1OctetString value = new Asn1OctetString(bytes);
        setFieldAs(index, value);
    }

    protected Integer getFieldAsInteger(EnumType index) {
        Asn1Integer value = getFieldAs(index, Asn1Integer.class);
        if (value != null && value.getValue() != null) {
            return value.getValue().intValue();
        }
        return null;
    }

    protected void setFieldAsInt(EnumType index, int value) {
        setFieldAs(index, new Asn1Integer(value));
    }

    protected void setFieldAsInt(EnumType index, BigInteger value) {
        setFieldAs(index, new Asn1Integer(value));
    }

    protected void setFieldAsObjId(EnumType index, String value) {
        setFieldAs(index, new Asn1ObjectIdentifier(value));
    }

    protected String getFieldAsObjId(EnumType index) {
        Asn1ObjectIdentifier objId = getFieldAs(index, Asn1ObjectIdentifier.class);
        if (objId != null) {
            return objId.getValue();
        }
        return null;
    }

    protected <T extends Asn1Type> T getFieldAsAny(EnumType index, Class<T> t) {
        Asn1Type value = fields[index.getValue()];
        if (value != null && value instanceof Asn1Any) {
            Asn1Any any = (Asn1Any) value;
            return any.getValueAs(t);
        }
        return null;
    }

    protected void setFieldAsAny(EnumType index, Asn1Type value) {
        if (value != null) {
            Asn1Any any = new Asn1Any(value);
            any.setDecodeInfo(fieldInfos[index.getValue()]);
            setFieldAs(index, any);
        }
    }

    protected void setAnyFieldValueType(EnumType index,
                                        Class<? extends Asn1Type> valueType) {
        if (valueType != null) {
            checkAndInitField(index.getValue());
            Asn1Type value = fields[index.getValue()];
            if (value != null && value instanceof Asn1Any) {
                Asn1Any any = (Asn1Any) value;
                any.setValueType(valueType);
            }
        }
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        dumper.indent(indents).appendType(getClass());
        dumper.append(simpleInfo()).newLine();

        String fdName;
        for (int i = 0; i < fieldInfos.length; i++) {
            fdName = fieldInfos[i].getIndex().getName();
            fdName = fdName.replace("_", "-").toLowerCase();

            dumper.indent(indents + 4).append(fdName).append(" = ");

            Asn1Type fdValue = fields[i];
            if (fdValue == null || fdValue instanceof Asn1Simple) {
                dumper.append((Asn1Simple<?>) fdValue);
            } else {
                dumper.newLine().dumpType(indents + 8, fdValue);
            }
            if (i < fieldInfos.length - 1) {
                dumper.newLine();
            }
        }
    }
}
