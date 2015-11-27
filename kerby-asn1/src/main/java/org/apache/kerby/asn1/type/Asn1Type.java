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

import org.apache.kerby.asn1.TagClass;
import org.apache.kerby.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The ASN1 type interface for all ASN1 types.
 */
public interface Asn1Type {
    /**
     * A mask to determinate if a Tag is CONSTRUCTED. The fifth bit should be
     * set to 1 if the type is constructed (0010-0000).
     */
    int CONSTRUCTED_FLAG = 0x20;

    /**
     * Encoding type
     */
    enum EncodingType {
        BER,
        DER,
        CER;
    }

    /**
     *
     * @return The tag class
     */
    TagClass tagClass();

    /**
     *
     * @return The tag flags
     */
    int tagFlags();

    /**
     * Get tag number for the type
     * @return tag number
     */
    int tagNo();

    /**
     * Use primitive or constructed.
     */
    void usePrimitive(boolean isPrimitive);

    /**
     * Tells if it is PRIMITIVE or not.
     *
     * @return true if using PRIMITIVE, false otherwise
     */
    boolean isPrimitive();

    /**
     * Use definitive length or not.
     * Note definitive length only makes sense when it's constructed.
     */
    void useDefinitiveLength(boolean isDefinitiveLength);

    /**
     * Tells if it's definitive length or not.
     * @return The boolean value
     */
    boolean isDefinitiveLength();

    /**
     * Use implicit or not.
     */
    void useImplicit(boolean isImplicit);

    /**
     * Tells if it's is IMPLICIT or not.
     *
     * @return true if using IMPLICIT, false otherwise
     */
    boolean isImplicit();

    /**
     * Set encoding type as DER.
     */
    void useDER();

    /**
     * Tells if it's is DER
     *
     * @return true if using DER, false otherwise
     */
    boolean isDER();

    /**
     * Set encoding type as BER.
     */
    void useBER();

    /**
     * Tells if it's is BER
     *
     * @return true if using BER, false otherwise
     */
    boolean isBER();

    /**
     * Set encoding type as CER.
     */
    void useCER();

    /**
     * Tells if it's is CER
     *
     * @return true if using CER, false otherwise
     */
    boolean isCER();

    /**
     * Get length of encoding bytes by just calculating without real encoding.
     * Generally it's called to prepare for the encoding buffer.
     * @return length of encoding bytes
     */
    int encodingLength();

    /**
     * Encode the type, by recursively.
     * @return encoded bytes
     */
    byte[] encode();

    /**
     * Encode the type, by recursively, using the provided buffer.
     * @param buffer The byte buffer
     */
    void encode(ByteBuffer buffer);

    /**
     * Decode the content bytes into this type.
     * @param content The content bytes
     * @throws IOException e
     */
    void decode(byte[] content) throws IOException;

    /**
     * Decode the content bytes into this type.
     * @param content The content bytes
     * @throws IOException e
     */
    void decode(ByteBuffer content) throws IOException;

    /**
     * Tag and encode this type using the provided tagging option.
     * @param taggingOption The tagging option
     * @return encoded bytes
     */
    byte[] taggedEncode(TaggingOption taggingOption);

    /**
     * Tag and encode this type using the provided tagging option.
     * @param buffer The byte buffer
     * @param taggingOption The tagging option
     */
    void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption);

    /**
     * Decode the content bytes into this type as it's tagged with the provided
     * tagging option.
     *
     * See {@link org.apache.kerby.asn1.TaggingOption}
     *
     * @param content The content bytes
     * @param taggingOption The tagging option
     * @throws IOException e
     */
    void taggedDecode(ByteBuffer content, TaggingOption taggingOption) throws IOException;

    /**
     * Decode the content bytes into this type as it's tagged with the provided
     * tagging option.
     *
     * See {@link org.apache.kerby.asn1.TaggingOption}
     *
     * @param content The content bytes
     * @param taggingOption The tagging option
     * @throws IOException e
     */
    void taggedDecode(byte[] content, TaggingOption taggingOption) throws IOException;
}
