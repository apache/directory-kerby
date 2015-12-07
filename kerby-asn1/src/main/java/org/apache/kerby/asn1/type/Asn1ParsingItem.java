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

import org.apache.kerby.asn1.Asn1Header;

/**
 * Asn1Item serves two purposes:
 * 1. Wrapping an existing Asn1Type value for Asn1Collection;
 * 2. Wrapping a half decoded value whose body content is left to be decoded
 * later when appropriate.
 * Why not fully decoded at once? Lazy and decode on demand for collection, or
 * impossible due to lacking key parameters.
 */
public class Asn1ParsingItem extends Asn1ParsingResult {

    public Asn1ParsingItem(Asn1Header header) {
        super(header);
    }

    @Override
    public String toString() {
        String valueStr = "##undecoded##";
        String typeStr = tag().isUniversal() ? tag().universalTag().toStr()
            : tag().tagClass().name().toLowerCase();
        return typeStr + " ["
            + "off=" + getOffset()
            + ", len=" + encodingHeaderLength() + "+" + encodingBodyLength()
            + "] "
            + valueStr;
    }
}
