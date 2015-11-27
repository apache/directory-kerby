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

import org.apache.kerby.asn1.type.Asn1Type;

/**
 * Tagging option for tagging an ASN1 type.
 */
public final class TaggingOption {
    private int tagNo;
    private boolean isImplicit;
    private boolean isAppSpecific;

    /**
     * Create an implicit application specific tagging option with tagNo.
     * @param tagNo The tag number
     * @return tagging option
     */
    public static TaggingOption newImplicitAppSpecific(int tagNo) {
        return new TaggingOption(tagNo, true, true);
    }

    /**
     * Create an explicit application specific tagging option with tagNo.
     * @param tagNo The tag number
     * @return tagging option
     */
    public static TaggingOption newExplicitAppSpecific(int tagNo) {
        return new TaggingOption(tagNo, false, true);
    }

    /**
     * Create an implicit context specific tagging option with tagNo.
     * @param tagNo The tag number
     * @return tagging option
     */
    public static TaggingOption newImplicitContextSpecific(int tagNo) {
        return new TaggingOption(tagNo, true, false);
    }

    /**
     * Create an explicit context specific tagging option with tagNo.
     * @param tagNo The tag number
     * @return tagging option
     */
    public static TaggingOption newExplicitContextSpecific(int tagNo) {
        return new TaggingOption(tagNo, false, false);
    }

    /**
     * The private constructor.
     * @param tagNo The tag number
     * @param isImplicit Implicit or not
     * @param isAppSpecific App specific or not
     */
    private TaggingOption(int tagNo, boolean isImplicit, boolean isAppSpecific) {
        this.tagNo = tagNo;
        this.isImplicit = isImplicit;
        this.isAppSpecific = isAppSpecific;
    }

    /**
     * Make tag flags giving it's tagged constructed.
     * @param isTaggedConstructed Tagged Constructed or not
     * @return tag flag
     */
    public int tagFlags(boolean isTaggedConstructed) {
        boolean isConstructed = isImplicit ? isTaggedConstructed : true;
        TagClass tagClass = isAppSpecific ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC;
        int flags = tagClass.getValue() | (isConstructed ? Asn1Type.CONSTRUCTED_FLAG : 0x00);

        return flags;
    }

    /**
     * Get the tag number.
     * @return tag number
     */
    public int getTagNo() {
        return tagNo;
    }

    /**
     * Tell it's application specific or not.
     * @return true if it's application specific otherwise false
     */
    public boolean isAppSpecific() {
        return isAppSpecific;
    }

    /**
     * Tell it's implicit or not.
     * @return true if it's implicit otherwise false
     */
    public boolean isImplicit() {
        return isImplicit;
    }
}
