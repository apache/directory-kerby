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
 * For collection type that may consist of dataTypeged fields
 */
public abstract class XdrStructType extends AbstractXdrType<XdrStructType> {
    private XdrFieldInfo[] fieldInfos;
    private XdrType[] fields;

    public XdrStructType(XdrDataType xdrDataType) {
        super(xdrDataType);
        this.fieldInfos = null;
        this.fields = null;
    }

    public XdrStructType(XdrDataType xdrDataType,
                         final XdrFieldInfo[] fieldInfos) {
        super(xdrDataType);
        this.fieldInfos = fieldInfos;
        this.fields = new XdrType[fieldInfos.length];

        getStructTypeInstance(this.fields, fieldInfos);
    }

    protected abstract void getStructTypeInstance(final XdrType[] fields, final XdrFieldInfo[] fieldInfos);

    public XdrFieldInfo[] getXdrFieldInfos() {
        return fieldInfos;
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        int allLen = 0;
        for (int i = 0; i < fields.length; ++i) {
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

    protected abstract XdrStructType fieldsToValues(AbstractXdrType[] fields);

    protected abstract AbstractXdrType[] getAllFields();
}
