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

import java.io.IOException;
import java.math.BigInteger;

public class XdrInteger extends XdrSimple<BigInteger> {
    public XdrInteger() {
        this((BigInteger) null);
    }

    public XdrInteger(Integer value) {
        this(BigInteger.valueOf(value));
    }

    public XdrInteger(Long value) {
        this(BigInteger.valueOf(value));
    }

    public XdrInteger(BigInteger value) {
        super(XdrDataType.INTEGER, value);
    }

    protected void toBytes() {
        setBytes(getValue().toByteArray());
    }

    protected void toValue() {
        setValue(new BigInteger(getBytes()));
    }

    @Override
    protected int encodingHeaderLength() throws IOException {
        return 0;
    }
}
