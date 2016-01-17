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
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;

/**
 * An ASN1 object has a tag.
 */
public abstract class Asn1Object {

    private final Tag tag;

    /**
     * Constructor with a tag
     * @param tag The tag
     */
    public Asn1Object(Tag tag) {
        this.tag = new Tag(tag);
    }

    /**
     * Default constructor with an universal tag.
     * @param tag the tag
     */
    public Asn1Object(UniversalTag tag) {
        this.tag = new Tag(tag);
    }

    /**
     * Constructor with a tag
     * @param tag The tag
     */
    public Asn1Object(int tag) {
        this.tag = new Tag(tag);
    }

    public Tag tag() {
        return tag;
    }

    public int tagFlags() {
        return tag().tagFlags();
    }

    public int tagNo() {
        return tag().tagNo();
    }

    public void usePrimitive(boolean isPrimitive) {
        tag().usePrimitive(isPrimitive);
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
        return tag().isEOC();
    }

    public boolean isNull() {
        return tag().isNull();
    }

    public boolean isSimple() {
        return Asn1Simple.isSimple(tag());
    }

    public boolean isCollection() {
        return Asn1Collection.isCollection(tag());
    }

    protected abstract int getHeaderLength() throws IOException;

    protected abstract int getBodyLength() throws IOException;

    protected String simpleInfo() {
        String simpleInfo = tag().typeStr();

        try {
            simpleInfo += " ["
                + "tag=" + tag()
                + ", len=" + getHeaderLength() + "+" + getBodyLength()
                + "] ";
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return simpleInfo;
    }
}
