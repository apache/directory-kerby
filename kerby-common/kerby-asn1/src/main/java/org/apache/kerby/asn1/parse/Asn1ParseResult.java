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

import org.apache.kerby.asn1.type.Asn1Object;
import org.apache.kerby.asn1.util.Asn1Util;

import java.nio.ByteBuffer;

public abstract class Asn1ParseResult extends Asn1Object {
    private Asn1Header header;
    private int bodyStart;
    private int bodyEnd;
    private ByteBuffer buffer;

    public Asn1ParseResult(Asn1Header header,
                           int bodyStart, ByteBuffer buffer) {
        super(header.getTag());
        this.header = header;
        this.bodyStart = bodyStart;
        this.buffer = buffer;

        this.bodyEnd = isDefinitiveLength() ? bodyStart + header.getLength() : -1;
    }

    public Asn1Header getHeader() {
        return header;
    }

    public int getBodyStart() {
        return bodyStart;
    }

    public int getBodyEnd() {
        return bodyEnd;
    }

    public void setBodyEnd(int bodyEnd) {
        this.bodyEnd = bodyEnd;
    }

    public ByteBuffer getBuffer() {
        return buffer;
    }

    public ByteBuffer getBodyBuffer() {
        ByteBuffer result = buffer.duplicate();
        result.position(bodyStart);

        int end = getBodyEnd();
        if (end >= bodyStart) {
            result.limit(end);
        }

        return result;
    }

    public byte[] readBodyBytes() {
        ByteBuffer bodyBuffer = getBodyBuffer();
        byte[] result = new byte[bodyBuffer.remaining()];
        bodyBuffer.get(result);
        return result;
    }

    public boolean isDefinitiveLength() {
        return header.isDefinitiveLength();
    }

    public int getEncodingLength() {
        return getHeaderLength() + getBodyLength();
    }

    public int getHeaderLength() {
        int bodyLen = getBodyLength();
        int headerLen = Asn1Util.lengthOfTagLength(header.getTag().tagNo());
        headerLen += (header.isDefinitiveLength()
            ? Asn1Util.lengthOfBodyLength(bodyLen) : 1);
        return headerLen;
    }

    public int getOffset() {
        return getBodyStart() - getHeaderLength();
    }

    public int getBodyLength() {
        if (isDefinitiveLength()) {
            return header.getLength();
        } else if (getBodyEnd() != -1) {
            return getBodyEnd() - getBodyStart();
        }
        return -1;
    }


    public boolean checkBodyFinished(int pos) {
        return getBodyEnd() != -1 && pos >= getBodyEnd();
    }

    @Override
    public String simpleInfo() {
        return tag().typeStr() + " ["
            + "tag=" + tag()
            + ", off=" + getOffset()
            + ", len=" + getHeaderLength() + "+" + getBodyLength()
            + "]";
    }
}
