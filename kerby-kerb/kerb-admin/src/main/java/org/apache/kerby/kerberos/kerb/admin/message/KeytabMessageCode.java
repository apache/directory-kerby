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
package org.apache.kerby.kerberos.kerb.admin.message;

import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;
import org.apache.kerby.xdr.type.XdrStructType;
import org.apache.kerby.xdr.type.XdrType;
import org.apache.kerby.xdr.type.XdrInteger;
import org.apache.kerby.xdr.type.XdrString;
import org.apache.kerby.xdr.type.XdrBytes;
import org.apache.kerby.xdr.type.AbstractXdrType;

/**
 * An extend XdrStructType to encode and decode ExportKeytab message.
 */
public class KeytabMessageCode extends XdrStructType {
    public KeytabMessageCode() {
        super(XdrDataType.STRUCT);
    }

    public KeytabMessageCode(XdrFieldInfo[] fieldInfos) {
        super(XdrDataType.STRUCT, fieldInfos);
    }

    @Override
    protected void getStructTypeInstance(XdrType[] fields, XdrFieldInfo[] fieldInfos) {
        for (int i = 0; i < fieldInfos.length; i++) {
            switch (fieldInfos[i].getDataType()) {
                case INTEGER:
                    fields[i] = new XdrInteger((Integer) fieldInfos[i].getValue());
                    break;
                case ENUM:
                    fields[i] = new AdminMessageEnum((AdminMessageType) fieldInfos[i].getValue());
                    break;
                case STRING:
                    fields[i] = new XdrString((String) fieldInfos[i].getValue());
                    break;
                case BYTES:
                    fields[i] = new XdrBytes((byte[]) fieldInfos[i].getValue());
                    break;
                default:
                    fields[i] = null;
            }
        }
    }

    @Override
    protected XdrStructType fieldsToValues(AbstractXdrType[] fields) {
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, fields[0].getValue());
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, fields[1].getValue());
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.BYTES, fields[2].getValue());
        return new KeytabMessageCode(xdrFieldInfos);
    }

    @Override
    protected AbstractXdrType[] getAllFields() {
        AbstractXdrType[] fields = new AbstractXdrType[4];
        fields[0] = new AdminMessageEnum();
        fields[1] = new XdrInteger();
        fields[2] = new XdrBytes();
        return fields;
    }
}
