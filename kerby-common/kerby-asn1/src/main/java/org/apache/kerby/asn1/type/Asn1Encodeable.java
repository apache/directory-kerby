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
import org.apache.kerby.asn1.TaggingOption;
import org.apache.kerby.asn1.UniversalTag;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1DerivedItem;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.util.Asn1Util;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The abstract ASN1 object for all the ASN1 types. It provides basic
 * encoding and decoding utilities.
 */
public abstract class Asn1Encodeable extends Asn1Object implements Asn1Type {

    protected int bodyLength = -1;
    public Asn1Encodeable outerEncodeable = null;

    // encoding options
    private EncodingType encodingType = EncodingType.BER;
    private boolean isImplicit = true;
    private boolean isDefinitiveLength = true; // by default!!

    /**
     * Constructor with a tag
     * @param tag The tag
     */
    public Asn1Encodeable(Tag tag) {
        super(tag);
    }

    /**
     * Default constructor with an universal tag.
     * @param tag the tag
     */
    public Asn1Encodeable(UniversalTag tag) {
        super(tag);
    }

    /**
     * Constructor with a tag
     * @param tag The tag
     */
    public Asn1Encodeable(int tag) {
        super(tag);
    }

    @Override
    public void usePrimitive(boolean isPrimitive) {
        tag().usePrimitive(isPrimitive);
    }

    @Override
    public boolean isPrimitive() {
        return tag().isPrimitive();
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
    public byte[] encode() throws IOException {
        int len = encodingLength();
        ByteBuffer byteBuffer = ByteBuffer.allocate(len);
        encode(byteBuffer);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void encode(ByteBuffer buffer) throws IOException {
        Asn1Util.encodeTag(buffer, tag());
        int bodyLen = getBodyLength();
        Asn1Util.encodeLength(buffer, bodyLen);
        encodeBody(buffer);
    }

    public void resetBodyLength() {
        if (bodyLength != -1) {
            bodyLength = -1;
            if (outerEncodeable != null) {
                outerEncodeable.resetBodyLength();
            }
        }
    }

    protected void encodeBody(ByteBuffer buffer) throws IOException { }

    @Override
    public void decode(byte[] content) throws IOException {
        decode(ByteBuffer.wrap(content));
    }

    @Override
    public int encodingLength() {
        return getHeaderLength() + getBodyLength();
    }

    @Override
    protected int getHeaderLength() {
        try {
            return encodingHeaderLength();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected int getBodyLength() {
        if (bodyLength == -1) {
            try {
                bodyLength = encodingBodyLength();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            if (bodyLength == -1) {
                throw new RuntimeException("Unexpected body length: -1");
            }
        }
        return bodyLength;
    }

    protected int encodingHeaderLength() throws IOException {
        int headerLen = Asn1Util.lengthOfTagLength(tagNo());
        int bodyLen = getBodyLength();
        headerLen += Asn1Util.lengthOfBodyLength(bodyLen);

        return headerLen;
    }

    protected abstract int encodingBodyLength() throws IOException;

    @Override
    public void decode(ByteBuffer content) throws IOException {
        Asn1ParseResult parseResult = Asn1Parser.parse(content);
        decode(parseResult);
    }

    public void decode(Asn1ParseResult parseResult) throws IOException {
        Asn1ParseResult tmpParseResult = parseResult;

        if (!tag().equals(parseResult.tag())) {
            // Primitive but using constructed encoding
            if (isPrimitive() && !parseResult.isPrimitive()) {
                Asn1Container container = (Asn1Container) parseResult;
                tmpParseResult = new Asn1DerivedItem(tag(), container);
            } else {
                throw new IOException("Unexpected item " + parseResult.simpleInfo()
                    + ", expecting " + tag());
            }
        }

        decodeBody(tmpParseResult);
    }

    protected abstract void decodeBody(Asn1ParseResult parseResult) throws IOException;

    protected int taggedEncodingLength(TaggingOption taggingOption) {
        int taggingTagNo = taggingOption.getTagNo();
        int taggingBodyLen = taggingOption.isImplicit() ? getBodyLength()
                : encodingLength();
        int taggingEncodingLen = Asn1Util.lengthOfTagLength(taggingTagNo)
                    + Asn1Util.lengthOfBodyLength(taggingBodyLen) + taggingBodyLen;
        return taggingEncodingLen;
    }

    @Override
    public byte[] taggedEncode(TaggingOption taggingOption) throws IOException {
        int len = taggedEncodingLength(taggingOption);
        ByteBuffer byteBuffer = ByteBuffer.allocate(len);
        taggedEncode(byteBuffer, taggingOption);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption) throws IOException {
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

    @Override
    public void taggedDecode(byte[] content,
                             TaggingOption taggingOption) throws IOException {
        taggedDecode(ByteBuffer.wrap(content), taggingOption);
    }

    @Override
    public void taggedDecode(ByteBuffer content,
                             TaggingOption taggingOption) throws IOException {
        Asn1ParseResult parseResult = Asn1Parser.parse(content);
        taggedDecode(parseResult, taggingOption);
    }

    public void taggedDecode(Asn1ParseResult parseResult,
                                TaggingOption taggingOption) throws IOException {
        Tag expectedTaggingTagFlags = taggingOption.getTag(!isPrimitive());

        Asn1ParseResult tmpParseResult = parseResult;
        if (!expectedTaggingTagFlags.equals(parseResult.tag())) {
            // Primitive but using constructed encoding
            if (isPrimitive() && !parseResult.isPrimitive()) {
                Asn1Container container = (Asn1Container) parseResult;
                tmpParseResult = new Asn1DerivedItem(tag(), container);
            } else {
                throw new IOException("Unexpected tag " + parseResult.tag()
                    + ", expecting " + expectedTaggingTagFlags);
            }
        }

        if (taggingOption.isImplicit()) {
            decodeBody(tmpParseResult);
        } else {

            Asn1Container container = (Asn1Container) parseResult;
            tmpParseResult = container.getChildren().get(0);
            
            decode(tmpParseResult);
        }
    }
}
