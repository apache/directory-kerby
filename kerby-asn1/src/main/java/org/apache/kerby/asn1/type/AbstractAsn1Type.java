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

/**
 * The abstract ASN1 type for all the ASN1 types. It provides basic
 * encoding and decoding utilities.
 *
 * @param <T> the type of the value encoded/decoded or wrapped by this
 */
public abstract class AbstractAsn1Type<T> extends Asn1Object {
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
        super(tagClass, tagNo);
        this.value = value;
    }

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        this.value = value;
    }
}
