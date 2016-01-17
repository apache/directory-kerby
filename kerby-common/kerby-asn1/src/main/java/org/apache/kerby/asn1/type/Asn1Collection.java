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
 * ASN1 complex type of multiple ASN1 objects.
 */
public class Asn1Collection extends Asn1Constructed {

    public Asn1Collection(UniversalTag universalTag) {
        super(new Tag(universalTag));
    }

    public static boolean isCollection(Tag tag) {
        return isCollection(tag.universalTag());
    }

    public static boolean isCollection(int tag) {
        return isCollection(new Tag(tag));
    }

    public static boolean isCollection(UniversalTag universalTag) {
        switch (universalTag) {
            case SEQUENCE:
            case SEQUENCE_OF:
            case SET:
            case SET_OF:
                return true;
            default:
                return false;
        }
    }

    public static Asn1Collection createCollection(Tag tag) {
        if (!isCollection(tag)) {
            throw new IllegalArgumentException("Not collection type, tag: " + tag);
        }
        return createCollection(tag.universalTag());
    }

    public static Asn1Collection createCollection(UniversalTag universalTag) {
        if (!isCollection(universalTag)) {
            throw new IllegalArgumentException("Not collection type, tag: " + universalTag);
        }

        switch (universalTag) {
            case SEQUENCE:
                return new Asn1Sequence();
            case SEQUENCE_OF:
                return new Asn1Sequence();
            case SET:
                return new Asn1Set();
            case SET_OF:
                return new Asn1Set();
            default:
                throw new IllegalArgumentException("Unexpected tag " + universalTag.getValue());
        }
    }
}
