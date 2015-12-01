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

import org.apache.kerby.asn1.Asn1Util;
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
        Asn1Util.encodeTag(buffer, tag());
        Asn1Util.encodeLength(buffer, encodingBodyLength());
        encodeBody(buffer);
    }

    protected void encodeBody(ByteBuffer buffer) { }

    @Override
    public void decode(byte[] content) throws IOException {
        decode(ByteBuffer.wrap(content));
    }

    @Override
    public int encodingLength() {
        if (encodingLen == -1) {
            int bodyLen = encodingBodyLength();
            encodingLen = Asn1Util.lengthOfTagLength(tagNo())
                + Asn1Util.lengthOfBodyLength(bodyLen) + bodyLen;
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

    @Override
    public void decode(ByteBuffer content) throws IOException {
        Tag tmpTag = Asn1Util.readTag(content);
        int length = Asn1Util.readLength(content);

        ByteBuffer valueBuffer;
        if (length == -1) {
            valueBuffer = content;
            useDefinitiveLength(false);
        } else {
            valueBuffer = Asn1Util.dupWithLength(content, length);
            useDefinitiveLength(true);
        }

        decode(tmpTag, valueBuffer);
    }

    public void decode(Tag tag, ByteBuffer content) throws IOException {
        if (!tag().equals(tag)) {
            throw new IOException("Unexpected tag " + tag
                    + ", expecting " + tag());
        }

        decodeBody(content);
    }

    protected abstract void decodeBody(ByteBuffer content) throws IOException;

    protected int taggedEncodingLength(TaggingOption taggingOption) {
        int taggingTagNo = taggingOption.getTagNo();
        int taggingBodyLen = taggingOption.isImplicit() ? encodingBodyLength()
                : encodingLength();
        int taggingEncodingLen = Asn1Util.lengthOfTagLength(taggingTagNo)
                + Asn1Util.lengthOfBodyLength(taggingBodyLen) + taggingBodyLen;
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
        Asn1Util.encodeTag(buffer, taggingTag);
        int taggingBodyLen = taggingOption.isImplicit() ? encodingBodyLength()
                : encodingLength();
        Asn1Util.encodeLength(buffer, taggingBodyLen);
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
        Tag taggingTag = Asn1Util.readTag(content);
        int taggingLength = Asn1Util.readLength(content);

        ByteBuffer valueBuffer;
        if (taggingLength == -1) {
            valueBuffer = content;
            useDefinitiveLength(false);
        } else {
            valueBuffer = Asn1Util.dupWithLength(content, taggingLength);
            useDefinitiveLength(true);
        }

        taggedDecode(taggingTag, valueBuffer, taggingOption);
    }

    protected void taggedDecode(Tag taggingTag, ByteBuffer content,
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

    public static Asn1Item decodeOne(ByteBuffer content) throws IOException {
        Tag tmpTag = Asn1Util.readTag(content);
        int length = Asn1Util.readLength(content);

        Asn1Item result;
        ByteBuffer valueBuffer;
        if (length == -1) {
            result = new Asn1Item(tmpTag);
            result.useDefinitiveLength(false);
            result.setBodyContent(content);
        } else {
            valueBuffer = Asn1Util.dupWithLength(content, length);
            result = new Asn1Item(tmpTag, valueBuffer);
            result.useDefinitiveLength(true);
        }

        return result;
    }
}
