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

import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;

public class Asn1OctetString extends Asn1Simple<byte[]> {
    public Asn1OctetString() {
        this(null);
    }

    public Asn1OctetString(byte[] value) {
        super(UniversalTag.OCTET_STRING, value);
    }

    @Override
    protected byte[] encodeBody() {
        return getValue();
    }

    @Override
    protected int encodingBodyLength() {
        return getValue().length;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        setValue(content.readAllLeftBytes());
    }
}
