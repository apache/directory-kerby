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

/**
 * ASN1, a tagged system.
 */
public class Tag {
    private int tagFlags = 0;
    private int tagNo = 0;

    public Tag(int tag) {
        this.tagFlags = tag & 0xE0;
        this.tagNo = tag & 0x1F;
    }

    public Tag(UniversalTag tag) {
        this.tagFlags = TagClass.UNIVERSAL.getValue();
        this.tagNo = tag.getValue();
    }

    public Tag(int tagFlags, int tagNo) {
        this.tagFlags = tagFlags & 0xE0;
        this.tagNo = tagNo;
    }

    public Tag(TagClass tagClass, int tagNo) {
        this.tagFlags = tagClass.getValue();
        this.tagNo = tagNo;
    }

    public Tag(Tag other) {
        this(other.tagFlags, other.tagNo);
    }

    public TagClass tagClass() {
        return TagClass.fromTag(tagFlags);
    }

    public void usePrimitive(boolean isPrimitive) {
        if (isPrimitive) {
            tagFlags &= ~0x20;
        } else {
            tagFlags |= 0x20;
        }
    }

    public boolean isPrimitive() {
        return (tagFlags & 0x20) == 0;
    }

    public int tagFlags() {
        return tagFlags;
    }

    public int tagNo() {
        return tagNo;
    }

    public UniversalTag universalTag() {
        if (isUniversal()) {
            return UniversalTag.fromValue(tagNo());
        }
        return UniversalTag.UNKNOWN;
    }

    public boolean isEOC() {
        return universalTag() == UniversalTag.EOC;
    }

    public boolean isNull() {
        return universalTag() == UniversalTag.NULL;
    }

    public boolean isUniversal() {
        return tagClass().isUniversal();
    }

    public boolean isAppSpecific() {
        return tagClass().isAppSpecific();
    }

    public boolean isContextSpecific() {
        return tagClass().isContextSpecific();
    }

    public boolean isSpecific() {
        return tagClass().isSpecific();
    }

    public byte tagByte() {
        int n = tagFlags | (tagNo < 0x1F ? tagNo : 0x1F);
        return (byte) (n & 0xFF);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Tag tag = (Tag) o;

        if (tagFlags != tag.tagFlags) {
            return false;
        }

        return tagNo == tag.tagNo;
    }

    @Override
    public int hashCode() {
        int result = tagFlags;
        result = 31 * result + tagNo;
        return result;
    }

    @Override
    public String toString() {
        return String.format("0x%02X", tagByte());
    }

    public String typeStr() {
        if (isUniversal()) {
            return universalTag().toStr();
        } else if (isAppSpecific()) {
            return "application [" + tagNo() + "]";
        } else {
            return "context [" + tagNo() + "]";
        }
    }

    public static Tag newAppTag(int tagNo) {
        return new Tag(TagClass.APPLICATION, tagNo);
    }

    public static Tag newCtxTag(int tagNo) {
        return new Tag(TagClass.CONTEXT_SPECIFIC, tagNo);
    }
}
