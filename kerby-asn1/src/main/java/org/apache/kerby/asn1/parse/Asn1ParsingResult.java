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
package org.apache.kerby.asn1.parse;

import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.util.Asn1Util;

import java.nio.ByteBuffer;

public abstract class Asn1ParsingResult {
    protected Asn1Header header;

    public Asn1ParsingResult(Asn1Header header) {
        this.header = header;
    }

    public Tag tag() {
        return header.getTag();
    }

    public int tagNo() {
        return tag().tagNo();
    }

    public boolean isPrimitive() {
        return tag().isPrimitive();
    }

    public boolean isUniversal() {
        return tag().isUniversal();
    }

    public boolean isAppSpecific() {
        return tag().isAppSpecific();
    }

    public boolean isContextSpecific() {
        return tag().isContextSpecific();
    }

    public boolean isTagSpecific() {
        return tag().isSpecific();
    }

    public boolean isEOC() {
        return header.isEOC();
    }

    public Asn1Header getHeader() {
        return header;
    }

    public boolean isDefinitiveLength() {
        return header.isDefinitiveLength();
    }

    public int getAllLength() {
        return getHeaderLength() + getBodyLength();
    }

    public int getHeaderLength() {
        int bodyLen = getBodyLength();
        int headerLen = Asn1Util.lengthOfTagLength(header.getTag().tagNo());
        headerLen += (header.isDefinitiveLength()
            ? Asn1Util.lengthOfBodyLength(bodyLen) : 1);
        return headerLen;
    }

    public int getBodyLength() {
        return header.getActualBodyLength();
    }

    protected int getOffset() {
        return header.getBodyStart() - getHeaderLength();
    }

    public byte[] readBodyBytes() {
        ByteBuffer bodyBuffer = header.getBodyBuffer();
        byte[] result = new byte[bodyBuffer.remaining()];
        bodyBuffer.get(result);
        return result;
    }
}
