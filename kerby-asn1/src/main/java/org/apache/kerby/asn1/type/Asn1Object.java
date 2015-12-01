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

import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.Tag;
import org.apache.kerby.asn1.TaggingOption;
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The abstract ASN1 object for all the ASN1 types. It provides basic
 * encoding and decoding utilities.
 */
public abstract class Asn1Object implements Asn1Type {
    private final Tag tag;

    private int encodingLen = -1;

    // encoding options
    private EncodingType encodingType = EncodingType.BER;
    private boolean isImplicit = true;
    private boolean isDefinitiveLength = false;

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

    @Override
    public Tag tag() {
        return tag;
    }

    protected int tagFlags() {
        return tag().tagFlags();
    }

    protected int tagNo() {
        return tag().tagNo();
    }

    @Override
    public void usePrimitive(boolean isPrimitive) {
        tag.usePrimitive(isPrimitive);
    }

    @Override
    public boolean isPrimitive() {
        return tag.isPrimitive();
    }

    @Override
    public void useDefinitiveLength(boolean isDefinitiveLength) {
        this.isDefinitiveLength = isDefinitiveLength;
    }

    @Override
    public boolean isDefinitiveLength() {
        return isDefinitiveLength;
    }

    @Override
    public void useImplicit(boolean isImplicit) {
        this.isImplicit = isImplicit;
    }

    @Override
    public boolean isImplicit() {
        return isImplicit;
    }

    @Override
    public void useDER() {
        this.encodingType = EncodingType.DER;
    }

    @Override
    public boolean isDER() {
        return encodingType == EncodingType.DER;
    }

    @Override
    public void useBER() {
        this.encodingType = EncodingType.BER;
    }

    @Override
    public boolean isBER() {
        return encodingType == EncodingType.BER;
    }

    @Override
    public void useCER() {
        this.encodingType = EncodingType.CER;
    }

    @Override
    public boolean isCER() {
        return encodingType == EncodingType.CER;
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
        encodeTag(buffer, tag());
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
    public int encodingLength() {
        if (encodingLen == -1) {
            int bodyLen = encodingBodyLength();
            encodingLen = lengthOfTagLength(tagNo())
                + lengthOfBodyLength(bodyLen) + bodyLen;
        }
        return encodingLen;
    }

    protected boolean isUniversal() {
        return tag.isUniversal();
    }

    protected boolean isAppSpecific() {
        return tag.isAppSpecific();
    }

    protected boolean isContextSpecific() {
        return tag.isContextSpecific();
    }

    protected boolean isTagged() {
        return tag.isTagged();
    }

    public boolean isSimple() {
        return Asn1Simple.isSimple(tag());
    }

    public boolean isCollection() {
        return Asn1Collection.isCollection(tag());
    }

    protected abstract int encodingBodyLength();

    protected void decode(LimitedByteBuffer content) throws IOException {
        Tag tmpTag = readTag(content);
        int length = readLength(content);

        decode(tmpTag, new LimitedByteBuffer(content, length));
    }

    public void decode(Tag tag, LimitedByteBuffer content) throws IOException {
        if (!tag().equals(tag)) {
            throw new IOException("Unexpected tag " + tag
                    + ", expecting " + tag());
        }

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
        Tag taggingTag = taggingOption.getTag(!isPrimitive());
        encodeTag(buffer, taggingTag);
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
        Tag taggingTag = readTag(content);
        int taggingLength = readLength(content);
        LimitedByteBuffer newContent = new LimitedByteBuffer(content, taggingLength);

        taggedDecode(taggingTag, newContent, taggingOption);
    }

    protected void taggedDecode(Tag taggingTag, LimitedByteBuffer content,
                                TaggingOption taggingOption) throws IOException {
        Tag expectedTaggingTagFlags = taggingOption.getTag(!isPrimitive());
        if (!expectedTaggingTagFlags.equals(taggingTag)) {
            throw new IOException("Unexpected tag " + taggingTag
                    + ", expecting " + expectedTaggingTagFlags);
        }

        if (taggingOption.isImplicit()) {
            decodeBody(content);
        } else {
            decode(content);
        }
    }

    public static Asn1Item decodeOne(LimitedByteBuffer content) throws IOException {
        Tag tmpTag = readTag(content);
        int length = readLength(content);
        if (length < 0) {
            throw new IOException("Unexpected length");
        }
        LimitedByteBuffer valueContent = new LimitedByteBuffer(content, length);
        content.skip(length);

        Asn1Item result = new Asn1Item(tmpTag, valueContent);
        if (result.isSimple()) {
            result.decodeValueAsSimple();
        }
        return result;
    }

    public static void skipOne(LimitedByteBuffer content) throws IOException {
        readTag(content);
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

    public static void encodeTag(ByteBuffer buffer, Tag tag) {
        int flags = tag.tagFlags();
        int tagNo = tag.tagNo();

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

    public static Tag readTag(LimitedByteBuffer buffer) throws IOException {
        int tagFlags = readTagFlags(buffer);
        int tagNo = readTagNo(buffer, tagFlags);
        return new Tag(tagFlags, tagNo);
    }

    private static int readTagFlags(LimitedByteBuffer buffer) throws IOException {
        int tagFlags = buffer.readByte() & 0xff;
        if (tagFlags == 0) {
            throw new IOException("Bad tag 0 found");
        }
        return tagFlags;
    }

    private static int readTagNo(LimitedByteBuffer buffer, int tagFlags) throws IOException {
        int tagNo = tagFlags & 0x1f;

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
