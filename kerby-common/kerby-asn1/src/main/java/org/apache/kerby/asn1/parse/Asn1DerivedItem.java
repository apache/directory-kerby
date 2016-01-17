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

/**
 * Combine multiple parts in a container into a single item, for primitive types
 * that use constructed encoding.
 */
public class Asn1DerivedItem extends Asn1Item {

    private final Asn1Container container;
    private final Tag newTag;
    private int newBodyLength;
    private ByteBuffer newBodyBuffer;

    public Asn1DerivedItem(Tag newTag, Asn1Container container) {
        super(container.getHeader(), container.getBodyStart(),
            container.getBuffer());

        this.newTag = newTag;
        this.container = container;
        this.newBodyLength = -1;
    }

    @Override
    public Tag tag() {
        return newTag;
    }

    private int computeBodyLength() {
        int totalLen = 0;
        for (Asn1ParseResult parseItem : container.getChildren()) {
            totalLen += parseItem.getBodyLength();
        }

        return totalLen;
    }

    private ByteBuffer makeBodyBuffer() {
        ByteBuffer tmpBuffer = ByteBuffer.allocate(getBodyLength());
        for (Asn1ParseResult parseItem : container.getChildren()) {
            tmpBuffer.put(parseItem.getBodyBuffer());
        }
        tmpBuffer.flip();

        return tmpBuffer;
    }

    @Override
    public ByteBuffer getBodyBuffer() {
        if (newBodyBuffer == null) {
            newBodyBuffer = makeBodyBuffer();
        }
        return newBodyBuffer;
    }

    @Override
    public int getBodyLength() {
        if (newBodyLength == -1) {
            newBodyLength = computeBodyLength();
        }

        return newBodyLength;
    }
}
