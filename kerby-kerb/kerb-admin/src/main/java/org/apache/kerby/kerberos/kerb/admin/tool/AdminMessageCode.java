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
package org.apache.kerby.kerberos.kerb.admin.tool;

import org.apache.kerby.KOptions;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;
import org.apache.kerby.xdr.type.*;

/**
 * An extend XdrStructType to encode and decode AdminMessage.
 */
public class AdminMessageCode extends XdrStructType {
    public AdminMessageCode() {
        super(XdrDataType.STRUCT);
    }

    public AdminMessageCode(XdrFieldInfo[] fieldInfos) {
        super(XdrDataType.STRUCT, fieldInfos);
    }

    protected  void getStructTypeInstance(final XdrType[] fields, final XdrFieldInfo[] fieldInfos) {
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
                default:
                    fields[i] = null;
            }

        }
    }

    @Override
    protected XdrStructType fieldsToValues(AbstractXdrType[] fields) {
        int paramNum = (int) fields[1].getValue();
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[paramNum + 2];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, fields[0].getValue());
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, fields[1].getValue());
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, fields[2].getValue());
        if (paramNum == 2 && fields[3].getValue() instanceof KOptions) {
            xdrFieldInfos[3] = new XdrFieldInfo(3, XdrDataType.STRUCT, fields[3].getValue()); /////koption
        } else if (paramNum == 2 && fields[3].getValue() instanceof String) {
            xdrFieldInfos[3] = new XdrFieldInfo(3, XdrDataType.STRING, fields[3].getValue());
        } else if (paramNum == 3) {
            xdrFieldInfos[3] = new XdrFieldInfo(3, XdrDataType.STRUCT, fields[3].getValue()); ////koption
            xdrFieldInfos[4] = new XdrFieldInfo(4, XdrDataType.STRING, fields[4].getValue());
        }
        return new AdminMessageCode(xdrFieldInfos);
    }

    @Override
    protected AbstractXdrType[] getAllFields() {
        AbstractXdrType[] fields = new AbstractXdrType[5];
        fields[0] = new AdminMessageEnum();
        fields[1] = new XdrInteger();
        fields[2] = new XdrString();
        fields[3] = new XdrString(); //suppose it is string
        fields[4] = null; // kOptions is not supported.
        return fields;
    }






}
