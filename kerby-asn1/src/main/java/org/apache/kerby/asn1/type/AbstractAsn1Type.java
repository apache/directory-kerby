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

import org.apache.kerby.asn1.EncodingOption;
import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.TagClass;
import org.apache.kerby.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The abstract ASN1 type for all the ASN1 types. It provides basic
 * encoding and decoding utilities.
 *
 * @param <T> the type of the value encoded/decoded or wrapped by this
 */
public abstract class AbstractAsn1Type<T> implements Asn1Type {
    private TagClass tagClass = TagClass.UNKNOWN;
    private int tagNo = -1;
    private int tagFlags = -1;
    private EncodingOption encodingOption = new EncodingOption();
    private int encodingLen = -1;
    // The wrapped real value.
    private T value;

    /**
     * Default constructor, generally for decoding as a value container
     * @param tagClass The tag class
     * @param tagNo The tag number
     */
    public AbstractAsn1Type(TagClass tagClass, int tagNo) {
        this(tagClass, tagNo, null);
    }

    /**
     * Default constructor, generally for decoding as a value container
     * @param tagFlags The tag flags
     * @param tagNo The tag number
     */
    public AbstractAsn1Type(int tagFlags, int tagNo) {
        this(tagFlags, tagNo, null);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param tagFlags The tag flags
     * @param tagNo The tag number
     * @param value The value
     */
    public AbstractAsn1Type(int tagFlags, int tagNo, T value) {
        this(TagClass.fromTagFlags(tagFlags), tagNo, value);
        setTagFlags(tagFlags);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param tagClass The tag class
     * @param tagNo The tag number
     * @param value The value
     */
    public AbstractAsn1Type(TagClass tagClass, int tagNo, T value) {
        this.tagClass = tagClass;
        this.tagNo = tagNo;
        this.value = value;
    }

    /**
     * Set encoding option
     * @param encodingOption The encoding option
     */
    public void setEncodingOption(EncodingOption encodingOption) {
        this.encodingOption = encodingOption;
    }

    /**
     * Get encoding option
     * @return encoding option
     */
    public EncodingOption getEncodingOption() {
        return this.encodingOption;
    }

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        this.value = value;
    }

    protected TagClass tagClass() {
        return tagClass;
    }

    @Override
    public int tagNo() {
        return tagNo;
    }

    protected void setTagFlags(int tagFlags) {
        this.tagFlags = tagFlags & 0xe0;
    }

    protected void setTagNo(int tagNo) {
        this.tagNo = tagNo;
    }

    @Override
    public byte[] encode() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(encodingLength());
        encode(byteBuffer);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void encode(ByteBuffer buffer) {
        encodeTag(buffer, tagFlags(), tagNo());
        encodeLength(buffer, encodingBodyLength());
        encodeBody(buffer);
    }

    protected void encodeBody(ByteBuffer buffer) { }

    @Override
    public void decode(byte[] content) throws IOException {
        decode(new LimitedByteBuffer(content));
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        decode(new LimitedByteBuffer(content));
    }

    @Override
    public int tagFlags() {
        if (tagFlags == -1) {
            int flags = tagClass.getValue();
            if (isConstructed()) {
                flags |= EncodingOption.CONSTRUCTED_FLAG;
            }
            return flags;
        }
        return tagFlags;
    }

    @Override
    public int encodingLength() {
        if (encodingLen == -1) {
            int bodyLen = encodingBodyLength();
            encodingLen = lengthOfTagLength(tagNo()) + lengthOfBodyLength(bodyLen) + bodyLen;
        }
        return encodingLen;
    }

    public boolean isConstructed() {
        if (tagFlags != -1) {
            return (tagFlags & EncodingOption.CONSTRUCTED_FLAG) != 0;
        } else {
            return false;
        }
    }

    public boolean isUniversal() {
        return tagClass.isUniversal();
    }

    public boolean isAppSpecific() {
        return tagClass.isAppSpecific();
    }

    public boolean isContextSpecific() {
        return tagClass.isContextSpecific();
    }

    public boolean isTagged() {
        return tagClass.isTagged();
    }

    public boolean isSimple() {
        return isUniversal() && Asn1Simple.isSimple(tagNo);
    }

    public boolean isCollection() {
        return isUniversal() && Asn1Collection.isCollection(tagNo);
    }

    protected abstract int encodingBodyLength();

    protected void decode(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        int tagNo = readTagNo(content, tag);
        int length = readLength(content);

        decode(tag, tagNo, new LimitedByteBuffer(content, length));
    }

    public void decode(int tagFlags, int tagNo,
                       LimitedByteBuffer content) throws IOException {
        if (this.tagClass != TagClass.UNKNOWN && this.tagClass
                != TagClass.fromTagFlags(tagFlags)) {
            throw new IOException("Unexpected tagFlags " + tagFlags
                    + ", expecting " + this.tagClass);
        }
        if (this.tagNo != -1 && this.tagNo != tagNo) {
            throw new IOException("Unexpected tagNo " + tagNo + ", "
                    + "expecting " + this.tagNo);
        }

        this.tagClass = TagClass.fromTagFlags(tagFlags);
        this.tagFlags = tagFlags;
        this.tagNo = tagNo;

        decodeBody(content);
    }

    protected abstract void decodeBody(LimitedByteBuffer content) throws IOException;

    protected int taggedEncodingLength(TaggingOption taggingOption) {
        int taggingTagNo = taggingOption.getTagNo();
        int taggingBodyLen = taggingOption.isImplicit() ? encodingBodyLength()
                : encodingLength();
        int taggingEncodingLen = lengthOfTagLength(taggingTagNo)
                + lengthOfBodyLength(taggingBodyLen) + taggingBodyLen;
        return taggingEncodingLen;
    }

    public byte[] taggedEncode(TaggingOption taggingOption) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(taggedEncodingLength(taggingOption));
        taggedEncode(byteBuffer, taggingOption);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption) {
        int taggingTagFlags = taggingOption.tagFlags(isConstructed());
        encodeTag(buffer, taggingTagFlags, taggingOption.getTagNo());
        int taggingBodyLen = taggingOption.isImplicit() ? encodingBodyLength()
                : encodingLength();
        encodeLength(buffer, taggingBodyLen);
        if (taggingOption.isImplicit()) {
            encodeBody(buffer);
        } else {
            encode(buffer);
        }
    }

    public void taggedDecode(byte[] content,
                             TaggingOption taggingOption) throws IOException {
        taggedDecode(ByteBuffer.wrap(content), taggingOption);
    }

    @Override
    public void taggedDecode(ByteBuffer content,
                             TaggingOption taggingOption) throws IOException {
        LimitedByteBuffer limitedBuffer = new LimitedByteBuffer(content);
        taggedDecode(limitedBuffer, taggingOption);
    }

    protected void taggedDecode(LimitedByteBuffer content,
                                TaggingOption taggingOption) throws IOException {
        int taggingTag = readTag(content);
        int taggingTagNo = readTagNo(content, taggingTag);
        int taggingLength = readLength(content);
        LimitedByteBuffer newContent = new LimitedByteBuffer(content, taggingLength);

        int tagFlags = taggingTag & 0xe0;
        taggedDecode(tagFlags, taggingTagNo, newContent, taggingOption);
    }

    protected void taggedDecode(int taggingTagFlags, int taggingTagNo,
                                LimitedByteBuffer content,
                                TaggingOption taggingOption) throws IOException {
        int expectedTaggingTagFlags = taggingOption.tagFlags(isConstructed());
        if (expectedTaggingTagFlags != taggingTagFlags) {
            throw new IOException("Unexpected tag flags " + taggingTagFlags
                    + ", expecting " + expectedTaggingTagFlags);
        }
        if (taggingOption.getTagNo() != taggingTagNo) {
            throw new IOException("Unexpected tagNo " + taggingTagNo + ", "
                    + "expecting " + taggingOption.getTagNo());
        }

        if (taggingOption.isImplicit()) {
            decodeBody(content);
        } else {
            decode(content);
        }
    }

    public static Asn1Item decodeOne(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        int tagNo = readTagNo(content, tag);
        int length = readLength(content);
        if (length < 0) {
            throw new IOException("Unexpected length");
        }
        LimitedByteBuffer valueContent = new LimitedByteBuffer(content, length);
        content.skip(length);

        Asn1Item result = new Asn1Item(tag, tagNo, valueContent);
        if (result.isSimple()) {
            result.decodeValueAsSimple();
        }
        return result;
    }

    public static void skipOne(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        readTagNo(content, tag);
        int length = readLength(content);
        if (length < 0) {
            throw new IOException("Unexpected length");
        }
        content.skip(length);
    }

    public static int lengthOfBodyLength(int bodyLength) {
        int length = 1;

        if (bodyLength > 127) {
            int payload = bodyLength;
            while (payload != 0) {
                payload >>= 8;
                length++;
            }
        }

        return length;
    }

    public static int lengthOfTagLength(int tagNo) {
        int length = 1;

        if (tagNo >= 31) {
            if (tagNo < 128) {
                length++;
            } else {
                length++;

                do {
                    tagNo >>= 7;
                    length++;
                } while (tagNo > 127);
            }
        }

        return length;
    }

    public static void encodeTag(ByteBuffer buffer, int flags, int tagNo) {
        if (tagNo < 31) {
            buffer.put((byte) (flags | tagNo));
        } else {
            buffer.put((byte) (flags | 0x1f));
            if (tagNo < 128) {
                buffer.put((byte) tagNo);
            } else {
                byte[] tmpBytes = new byte[5]; // 5 * 7 > 32
                int iPut = tmpBytes.length;

                tmpBytes[--iPut] = (byte) (tagNo & 0x7f);
                do {
                    tagNo >>= 7;
                    tmpBytes[--iPut] = (byte) (tagNo & 0x7f | 0x80);
                } while (tagNo > 127);

                buffer.put(tmpBytes, iPut, tmpBytes.length - iPut);
            }
        }
    }

    public static void encodeLength(ByteBuffer buffer, int bodyLength) {
        if (bodyLength < 128) {
            buffer.put((byte) bodyLength);
        } else {
            int length = 0;
            int payload = bodyLength;

            while (payload != 0) {
                payload >>= 8;
                length++;
            }

            buffer.put((byte) (length | 0x80));

            payload = bodyLength;
            for (int i = length - 1; i >= 0; i--) {
                buffer.put((byte) (payload >> (i * 8)));
            }
        }
    }

    public static int readTag(LimitedByteBuffer buffer) throws IOException {
        int tag = buffer.readByte() & 0xff;
        if (tag == 0) {
            throw new IOException("Bad tag 0 found");
        }
        return tag;
    }

    public static int readTagNo(LimitedByteBuffer buffer, int tag) throws IOException {
        int tagNo = tag & 0x1f;

        if (tagNo == 0x1f) {
            tagNo = 0;

            int b = buffer.readByte() & 0xff;
            if ((b & 0x7f) == 0) {
                throw new IOException("Invalid high tag number found");
            }

            while (b >= 0 && (b & 0x80) != 0) {
                tagNo |= b & 0x7f;
                tagNo <<= 7;
                b = buffer.readByte();
            }

            tagNo |= b & 0x7f;
        }

        return tagNo;
    }

    public static int readLength(LimitedByteBuffer buffer) throws IOException {
        int bodyLength = buffer.readByte() & 0xff;

        if (bodyLength > 127) {
            int length = bodyLength & 0x7f;
            if (length > 4) {
                throw new IOException("Bad bodyLength of more than 4 bytes: " + length);
            }

            bodyLength = 0;
            int tmp;
            for (int i = 0; i < length; i++) {
                tmp = buffer.readByte() & 0xff;
                bodyLength = (bodyLength << 8) + tmp;
            }

            if (bodyLength < 0) {
                throw new IOException("Invalid bodyLength " + bodyLength);
            }
            if (bodyLength > buffer.hasLeft()) {
                throw new IOException("Corrupt stream - less data "
                        + buffer.hasLeft() + " than expected " + bodyLength);
            }
        }

        return bodyLength;
    }
}
