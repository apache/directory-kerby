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

import org.apache.kerby.xdr.EnumType;
import org.apache.kerby.xdr.XdrDataType;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public abstract class XdrEnumerated<T extends EnumType> extends XdrSimple<T> {
    /**
     * Default constructor, generally for decoding as a container
     */
    public XdrEnumerated() {
        this(null);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param value The Enum value
     */
    public XdrEnumerated(T value) {
        super(XdrDataType.ENUM, value);
    }

    protected void toBytes() {
        byte[] bytes = ByteBuffer.allocate(4).putInt(getValue().getValue()).array();
        setBytes(bytes);
    }

    protected void toValue() {
        if (getBytes().length != 4) {
            byte[] intBytes = ByteBuffer.allocate(4).put(getBytes(), 0, 4).array();
            setBytes(intBytes); /**reset bytes in case the enum type is in a struct or union*/
        }
        BigInteger biVal = new BigInteger(getBytes());
        int iVal = biVal.intValue();
        EnumType[] allValues = getAllEnumValues();
        for (EnumType val : allValues) {
            if (val.getValue() == iVal) {
                setValue((T) val);
            }
        }
    }

    protected abstract EnumType[] getAllEnumValues();
}
