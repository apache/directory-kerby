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

/**
 * The abstract ASN1 type for all the ASN1 types. It provides basic
 * encoding and decoding utilities.
 *
 * @param <T> the type of the value encoded/decoded or wrapped by this
 */
public abstract class AbstractAsn1Type<T> extends Asn1Encodeable {
    // The wrapped real value.
    private T value;

    /**
     * Default constructor.
     * @param tag the tag
     * @param value the value
     */
    public AbstractAsn1Type(Tag tag, T value) {
        super(tag);
        this.value = value;
    }

    /**
     * Default constructor.
     * @param tag the tag
     */
    public AbstractAsn1Type(Tag tag) {
        super(tag);
    }

    /**
     * Default constructor with an universal tag.
     * @param tag the tag
     * @param value the value
     */
    public AbstractAsn1Type(UniversalTag tag, T value) {
        super(tag);
        this.value = value;
    }

    /**
     * Default constructor with an universal tag.
     * @param tag the tag
     */
    public AbstractAsn1Type(UniversalTag tag) {
        super(tag);
    }

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        resetBodyLength();
        this.value = value;
        if (value instanceof Asn1Encodeable) {
            ((Asn1Encodeable) value).outerEncodeable = this;
        }
    }

    @Override
    public String toString() {
        return tag().typeStr();
    }
}
