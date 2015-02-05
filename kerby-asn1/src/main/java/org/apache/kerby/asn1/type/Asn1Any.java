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

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1Any extends AbstractAsn1Type<Asn1Type> {

    public Asn1Any(Asn1Type anyValue) {
        super(anyValue.tagFlags(), anyValue.tagNo(), anyValue);
    }

    @Override
    protected int encodingBodyLength() {
        return ((AbstractAsn1Type<?>) getValue()).encodingBodyLength();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        ((AbstractAsn1Type<?>) getValue()).encodeBody(buffer);
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        ((AbstractAsn1Type<?>) getValue()).decodeBody(content);
    }
}
