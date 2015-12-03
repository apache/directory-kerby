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
package org.apache.kerby.asn1;

import java.nio.ByteBuffer;

public class Asn1Header {
    private Tag tag;
    private int length;
    private ByteBuffer valueBuffer;

    public Asn1Header(Tag tag, int length, ByteBuffer valueBuffer) {
        this.tag = tag;
        this.length = length;
        this.valueBuffer = valueBuffer;
    }

    public Tag getTag() {
        return tag;
    }

    public int getLength() {
        return length;
    }

    public ByteBuffer getValueBuffer() {
        return valueBuffer;
    }

    public boolean isEOC() {
        return length == 0 && tag.isEOC();
    }

    public boolean isDefinitiveLength() {
        return length != -1;
    }
}
