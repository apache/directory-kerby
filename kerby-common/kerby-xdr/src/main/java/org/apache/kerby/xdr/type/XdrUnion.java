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
package org.apache.kerby.xdr.type;

import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * A discriminated union is a type composed of a discriminant followed
 * by a type selected from a set of prearranged types according to the
 * value of the discriminant.  The type of discriminant is either "int",
 * "unsigned int", or an enumerated type, such as "bool".  The component
 * types are called "arms" of the union and are preceded by the value of
 * the discriminant that implies their encoding.  Discriminated unions
 * are declared as follows:
 *
 *  union switch (discriminant-declaration) {
 *      case discriminant-value-A:
 *          arm-declaration-A;
 *      case discriminant-value-B:
 *          arm-declaration-B;
 *      ...
 *      default: default-declaration;
 *  } identifier;
 * Each "case" keyword is followed by a legal value of the discriminant.
 * The default arm is optional.  If it is not specified, then a valid
 * encoding of the union cannot take on unspecified discriminant values.
 * The size of the implied arm is always a multiple of four bytes.
 *
 * The discriminated union is encoded as its discriminant followed by
 * the encoding of the implied arm.
 *                  0   1   2   3
 *                  +---+---+---+---+---+---+---+---+
 *                  |  discriminant |  implied arm  |
 *                  +---+---+---+---+---+---+---+---+
 *                  |<---4 bytes--->|
 */
public abstract class XdrUnion extends AbstractXdrType<XdrUnion> {
    /**
     * [0] is the discriminant
     *      index, XdrDataType, value;
     * [1] is the implied arm
     */
    private XdrFieldInfo[] fieldInfos;
    private XdrType[] fields;

    public XdrUnion(XdrDataType xdrDataType) {
        super(xdrDataType);
        this.fieldInfos = null;
        this.fields = null;
    }

    public XdrUnion(XdrDataType xdrDataType,
                         final XdrFieldInfo[] fieldInfos) {
        super(xdrDataType);
        this.fieldInfos = fieldInfos;
        this.fields = new XdrType[fieldInfos.length];

        getUnionInstance(this.fields, fieldInfos);
    }

    protected abstract void getUnionInstance(final XdrType[] fields, final XdrFieldInfo[] fieldInfos);

    public XdrFieldInfo[] getXdrFieldInfos() {
        return fieldInfos;
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        int allLen = 0;
        for (int i = 0; i < fields.length; i++) {
            AbstractXdrType field = (AbstractXdrType) fields[i];
            if (field != null) {
                allLen += field.encodingLength();
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) throws IOException {
        for (int i = 0; i < fields.length; ++i) {
            XdrType field = fields[i];
            if (field != null) {
                field.encode(buffer);
            }
        }
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        AbstractXdrType[] fields = getAllFields();
        Object[] value;
        for (int i = 0; i < fields.length; i++) {
            if (fields[i] != null) {
                fields[i].decode(content);
                int length = fields[i].encodingLength();
                byte[] array = content.array();
                byte[] newArray = new byte[array.length - length];
                System.arraycopy(array, length, newArray, 0, array.length - length);
                content = ByteBuffer.wrap(newArray);
            }
        }
        this.fields = fields;
        setValue(fieldsToValues(fields));
    }

    protected abstract XdrUnion fieldsToValues(AbstractXdrType[] fields);

    protected abstract AbstractXdrType[] getAllFields();
}
