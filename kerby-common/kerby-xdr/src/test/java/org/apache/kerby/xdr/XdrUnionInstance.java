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
import org.apache.kerby.xdr.type.XdrEnumerated;
import org.apache.kerby.xdr.type.XdrInteger;
import org.apache.kerby.xdr.type.XdrString;
import org.apache.kerby.xdr.type.XdrType;
import org.apache.kerby.xdr.type.XdrUnion;
import org.apache.kerby.xdr.type.XdrUnsignedInteger;

enum FileKind implements EnumType {
    TEXT,
    DATA,
    EXEC;

    public int getValue() {
        return ordinal();
    }

    public String getName() {
        return name();
    }
}

class FileKindEnumeratedInstance extends XdrEnumerated<FileKind> {

    FileKindEnumeratedInstance() {
        super(null);
    }

    FileKindEnumeratedInstance(FileKind value) {
        super(value);
    }
    @Override
    protected EnumType[] getAllEnumValues() {
        return FileKind.values();
    }

}

class UnionFileTypeSwitch {
    FileKind fileKind;
    Object arm;
    UnionFileTypeSwitch(FileKind fileKind) {
        this.fileKind = fileKind;
        switch (fileKind) {
            case TEXT:
                arm = null;
                break;
            case DATA:
                arm = "creator";
                break;
            case EXEC:
                arm = "lisp";
                break;
        }
    }

    XdrDataType getFileKind() {
        return XdrDataType.ENUM;
    }

    FileKind getFileValue() {
        return fileKind;
    }

    XdrDataType getArmKind() {
        XdrDataType xdrDataType = XdrDataType.UNKNOWN;
        switch (fileKind) {
            case TEXT:
                xdrDataType = XdrDataType.UNKNOWN;
                break;
            case DATA:
                xdrDataType = XdrDataType.STRING;
                break;
            case EXEC:
                xdrDataType = XdrDataType.STRING;
                break;
        }
        return xdrDataType;
    }

    Object getArmValue() {
        return arm;
    }
}

public class XdrUnionInstance extends XdrUnion {

    public XdrUnionInstance() {
        super(XdrDataType.UNION);
    }

    public XdrUnionInstance(XdrFieldInfo[] fieldInfos) {
        super(XdrDataType.UNION, fieldInfos);
    }


    @Override
    protected void getUnionInstance(XdrType[] fields, XdrFieldInfo[] fieldInfos) {
        switch (fieldInfos[0].getDataType()) {
            case INTEGER:
                fields[0] = new XdrInteger((Integer) fieldInfos[0].getValue());
                break;
            case UNSIGNED_INTEGER:
                fields[0] = new XdrUnsignedInteger((Long) fieldInfos[0].getValue());
                break;
            case BOOLEAN:
                fields[0] = new XdrBoolean((Boolean) fieldInfos[0].getValue());
                break;
            case ENUM:
                fields[0] = new FileKindEnumeratedInstance((FileKind) fieldInfos[0].getValue());
                break;
            default:
                throw new RuntimeException("Wrong discriminant type for union: " + fieldInfos[0].getDataType());
        }

        switch (fieldInfos[1].getDataType()) {
            case INTEGER:
                fields[1] = new XdrInteger((Integer) fieldInfos[1].getValue());
                break;
            case UNSIGNED_INTEGER:
                fields[1] = new XdrUnsignedInteger((Long) fieldInfos[1].getValue());
                break;
            case BOOLEAN:
                fields[1] = new XdrBoolean((Boolean) fieldInfos[1].getValue());
                break;
            case STRING:
                fields[1] = new XdrString((String) fieldInfos[1].getValue());
                break;
            default:
                fields[1] = null;
        }
    }

    @Override
    protected XdrUnion fieldsToValues(AbstractXdrType[] fields) {
        XdrFieldInfo[] fieldInfos = {new XdrFieldInfo(0, XdrDataType.ENUM, fields[0].getValue()),
                new XdrFieldInfo(1, XdrDataType.STRING, fields[1].getValue())};
        return new XdrUnionInstance(fieldInfos);
    }

    @Override
    protected AbstractXdrType[] getAllFields() {
        AbstractXdrType[] fields = new AbstractXdrType[2];
        fields[0] = new FileKindEnumeratedInstance();
        fields[1] = new XdrString();
        return fields;
    }
}
