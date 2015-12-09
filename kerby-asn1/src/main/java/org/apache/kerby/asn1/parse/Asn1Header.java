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

import java.nio.ByteBuffer;

public class Asn1Header {
    private Tag tag;
    private int length;
    private int bodyStart;
    private int bodyEnd;
    private ByteBuffer buffer;

    public Asn1Header(Tag tag, int length,
                      int bodyStart, ByteBuffer buffer) {
        this.tag = tag;
        this.length = length;
        this.bodyStart = bodyStart;
        this.buffer = buffer;

        this.bodyEnd = isDefinitiveLength() ? bodyStart + length : -1;
    }

    public Tag getTag() {
        return tag;
    }

    public int getActualBodyLength() {
        if (isDefinitiveLength()) {
            return getLength();
        } else if (getBodyEnd() != -1) {
            return getBodyEnd() - getBodyStart();
        }
        return -1;
    }

    public int getLength() {
        return length;
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

    public boolean isEOC() {
        return length == 0 && tag.isEOC();
    }

    public boolean isDefinitiveLength() {
        return length != -1;
    }

    public boolean checkBodyFinished(int pos) {
        return getBodyEnd() != -1 && pos >= getBodyEnd();
    }
}
