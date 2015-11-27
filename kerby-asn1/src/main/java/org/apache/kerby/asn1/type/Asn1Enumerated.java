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

import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;
import java.math.BigInteger;

/**
 * The ASN1 enumerated type
 */
public abstract class Asn1Enumerated<T extends Asn1EnumType> extends Asn1Simple<T> {

    /**
     * Default constructor, generally for decoding as a container
     */
    public Asn1Enumerated() {
        this(null);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param value The boolean value
     */
    public Asn1Enumerated(T value) {
        super(UniversalTag.ENUMERATED, value);
    }

    protected void toBytes() {
        BigInteger biValue = BigInteger.valueOf(getValue().getValue());
        setBytes(biValue.toByteArray());
    }

    protected void toValue() throws IOException {
        BigInteger biVal = new BigInteger(getBytes());
        int iVal = biVal.intValue();
        Asn1EnumType[] allValues = getAllEnumValues();
        for (Asn1EnumType val : allValues) {
            if (val.getValue() == iVal) {
                setValue((T) val);
            }
        }
    }

    protected abstract Asn1EnumType[] getAllEnumValues();
}
