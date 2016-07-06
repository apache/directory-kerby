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
package org.apache.kerby.xdr;

import org.apache.kerby.xdr.type.AbstractXdrType;
import org.apache.kerby.xdr.type.XdrBoolean;
import org.apache.kerby.xdr.type.XdrInteger;
import org.apache.kerby.xdr.type.XdrString;
import org.apache.kerby.xdr.type.XdrStructType;
import org.apache.kerby.xdr.type.XdrType;
import org.apache.kerby.xdr.type.XdrUnion;
import org.apache.kerby.xdr.type.XdrUnsignedInteger;

class MyFile {
    String fileName;
    UnionFileTypeSwitch fileType;
    String owner;

    MyFile(String name, UnionFileTypeSwitch fileType, String owner) {
        this.fileName = name;
        this.fileType = fileType;
        this.owner = owner;
    }

    public String getFileName() {
        return fileName;
    }

    public UnionFileTypeSwitch getFileType() {
        return fileType;
    }

    public String getOwner() {
        return owner;
    }

}

public class XdrStructTypeInstance extends XdrStructType {
    public XdrStructTypeInstance() {
        super(XdrDataType.STRUCT);
    }

    public XdrStructTypeInstance(XdrFieldInfo[] fieldInfos) {
        super(XdrDataType.STRUCT, fieldInfos);
    }

    protected  void getStructTypeInstance(final XdrType[] fields, final XdrFieldInfo[] fieldInfos) {
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
                    fields[i] = new FileKindEnumeratedInstance((FileKind) fieldInfos[i].getValue());
                    break;
                case UNION:
                    fields[i] = (XdrUnion) fieldInfos[i].getValue();
                    break;
                case STRING:
                    fields[i] = new XdrString((String) fieldInfos[i].getValue());
                    break;
                case STRUCT:
                    fields[i] = new XdrStructTypeInstance((XdrFieldInfo[]) fieldInfos[i].getValue());
                default:
                    fields[i] = null;
            }
        }

    }

    @Override
    protected XdrStructType fieldsToValues(AbstractXdrType[] fields) {
        XdrFieldInfo[] fieldInfos = {new XdrFieldInfo(0, XdrDataType.STRING, fields[0].getValue()),
                new XdrFieldInfo(1, XdrDataType.UNION, fields[1].getValue()),
                new XdrFieldInfo(2, XdrDataType.STRING, fields[2].getValue())};
        return new XdrStructTypeInstance(fieldInfos);
    }

    @Override
    protected AbstractXdrType[] getAllFields() {
        AbstractXdrType[] fields = new AbstractXdrType[3];
        fields[0] = new XdrString();
        fields[1] = new XdrUnionInstance();
        fields[2] = new XdrString();
        return fields;
    }
}
