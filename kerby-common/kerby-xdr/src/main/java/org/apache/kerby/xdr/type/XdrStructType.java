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
public class XdrStructType extends AbstractXdrType<XdrStructType> {
    private final XdrFieldInfo[] fieldInfos;
    private final XdrType[] fields;

    public XdrStructType(XdrDataType xdrDataType,
                         final XdrFieldInfo[] fieldInfos) {
        super(xdrDataType);

        setValue(this);
        this.fieldInfos = fieldInfos;
        this.fields = new XdrType[fieldInfos.length];
        for (int i = 0; i < fieldInfos.length; i++) {
            switch (fieldInfos[i].getDataType()) {
                case INTEGER:
                    fields[i] = new XdrInteger((Integer) fieldInfos[i].getValue());
                    break;
                case UNSIGNED_INTEGER:
                    fields[i] = new XdrUnsignedInteger((Long) fieldInfos[i].getValue());
                    break;
                case BOOLEAN:
                    fields[i] = new XdrBoolean((Boolean) fieldInfos[i].getValue());
                    break;
                case ENUM:
                    //fields[i] = new XdrInteger((Integer) fieldInfos[i].getValue());
                    break;
                case STRING:
                    fields[i] = new XdrString((String) fieldInfos[i].getValue());
                    break;
                case STRUCT:
                    //fields[i] = new XdrStructType(fieldInfos[i].getValue());
                    break;
            }
        }
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
}
