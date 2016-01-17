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

import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;

/**
 * Application or context specific object mainly for using implicit encoding.
 */
public class Asn1Specific extends AbstractAsn1Type<byte[]> {

    public Asn1Specific(Tag tag, byte[] value) {
        super(tag, value);
    }

    public Asn1Specific(Tag tag) {
        super(tag);
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() != null) {
            return getValue().length;
        }
        return 0;
    }

    @Override
    protected void decodeBody(Asn1ParseResult parseResult) throws IOException {
        setValue(parseResult.readBodyBytes());
    }

    @Override
    public String toString() {
        return tag().typeStr() + "  <" + getValue().length + " bytes>";
    }
}
