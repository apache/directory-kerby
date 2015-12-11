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
    protected int encodingBodyLength() {
        int allLen = 0;
        for (int i = 0; i < fields.length; ++i) {
            AbstractAsn1Type<?> field = (AbstractAsn1Type<?>) fields[i];
            if (field != null) {
                if (fieldInfos[i].isTagged()) {
                    TaggingOption taggingOption =
                        fieldInfos[i].getTaggingOption();
                    allLen += field.taggedEncodingLength(taggingOption);
                } else {
                    allLen += field.encodingLength();
                }
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
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
        checkAndInitFields();

        Asn1Container container = (Asn1Container) parseResult;
        List<Asn1ParseResult> parseResults = container.getChildren();

        int lastPos = -1, foundPos = -1;

        for (Asn1ParseResult parseItem : parseResults) {
            if (parseItem.isEOC() || parseItem.isNull()) {
                continue;
            }

            foundPos = match(lastPos, parseItem);
            if (foundPos == -1) {
                throw new IOException("Unexpected item: " + parseItem.typeStr());
            }
            lastPos = foundPos;

            Asn1Type fieldValue = fields[foundPos];
            if (fieldValue instanceof Asn1Any) {
                Asn1Any any = (Asn1Any) fieldValue;
                any.setFieldInfo(fieldInfos[foundPos]);
                Asn1Binder.bind(parseItem, any);
            } else {
                if (parseItem.isContextSpecific()) {
                    Asn1Binder.bindWithTagging(parseItem, fieldValue,
                            fieldInfos[foundPos].getTaggingOption());
                } else {
                    Asn1Binder.bind(parseItem, fieldValue);
                }
            }
        }
    }

    private int match(int lastPos, Asn1ParseResult parseItem) {
        int foundPos = -1;
        for (int i = lastPos + 1; i < fieldInfos.length; ++i) {
            if (parseItem.isContextSpecific()) {
                if (fieldInfos[i].getTagNo() == parseItem.tagNo()) {
                    foundPos = i;
                    break;
                }
            } else if (fields[i].tag().equals(parseItem.tag())) {
                foundPos = i;
                break;
            } else if (fields[i] instanceof Asn1Choice) {
                Asn1Choice aChoice = (Asn1Choice) fields[i];
                if (aChoice.matchAndSetValue(parseItem.tag())) {
                    foundPos = i;
                    break;
                }
            } else if (fields[i] instanceof Asn1Any) {
                foundPos = i;
                break;
            }
        }

        return foundPos;
    }

    private void checkAndInitFields() {
        for (int i = 0; i < fieldInfos.length; ++i) {
            if (fields[i] == null) {
                fields[i] = fieldInfos[i].createFieldValue();
            }
        }
    }

    protected abstract Asn1Collection createCollection();

    protected <T extends Asn1Type> T getFieldAs(EnumType index, Class<T> t) {
        Asn1Type value = fields[index.getValue()];
        if (value == null) {
            return null;
        }
        return (T) value;
    }

    protected void setFieldAs(EnumType index, Asn1Type value) {
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

    protected void setFieldAsBigInteger(EnumType index, BigInteger value) {
        setFieldAs(index, new Asn1Integer(value));
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
            setFieldAs(index, new Asn1Any(value));
        }
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        dumper.dumpTypeInfo(indents, getClass());

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
