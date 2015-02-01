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
 * An enum used to represent the various Encoding options.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum EncodingOption {
    UNKNOWN(-1),
    PRIMITIVE(1),
    CONSTRUCTED(2),
    CONSTRUCTED_DEFLEN(3),
    CONSTRUCTED_INDEFLEN(4),
    IMPLICIT(5),
    EXPLICIT(6),
    BER(7),
    DER(8),
    CER(9);

    /** 
     * A mask to determinate if a Tag is CONSTRUCTED. The fifth bit should be set to 1 if
     * the type is constructed (0010-0000).
     */
    public static int CONSTRUCTED_FLAG = 0x20;

    /** The associated value */
    private int value;

    /** Create a instance of EncodingOption */
    private EncodingOption(int value) {
        this.value = value;
    }


    /**
     * @return The integer value associated with the EncodingOption instance
     */
    public int getValue() {
        return value;
    }

    public static boolean isConstructed(int tag) {
        return (tag & CONSTRUCTED_FLAG) != 0;
    }

    /**
     * Tells if the EncodingOption is PRIMITIVE
     * 
     * @return true if using PRIMITIVE, false otherwise
     */
    public boolean isPrimitive() {
        return this == PRIMITIVE;
    }

    /**
     * Tells if the EncodingOption is for an encoded type (CONSTRUCTED, CONSTRUCTED_DEFLEN
     * or CONSTRUCTED_INDEFLEN)
     * 
     * @return true if the EncodingOption is CONSTRUCTED, false otherwise
     */
    public boolean isConstructed() {
        return this == CONSTRUCTED || this == CONSTRUCTED_DEFLEN || this == CONSTRUCTED_INDEFLEN;
    }

    /**
     * Tells if the EncodingOption is IMPLICIT
     * 
     * @return true if using IMPLICIT, false otherwise
     */
    public boolean isImplicit() {
        return this == IMPLICIT;
    }

    /**
     * Tells if the EncodingOption is EXPLICIT
     * 
     * @return true if using EXPLICIT, false otherwise
     */
    public boolean isExplicit() {
        return this == EXPLICIT;
    }

    /**
     * Tells if the EncodingOption is DER
     * 
     * @return true if using DER, false otherwise
     */
    public boolean isDer() {
        return this == DER;
    }

    /**
     * Tells if the EncodingOption is CER
     * 
     * @return true if using CER, false otherwise
     */
    public boolean isCer() {
        return this == CER;
    }

    /**
     * Tells if the EncodingOption is BER
     * 
     * @return true if using BER, false otherwise
     */
    public boolean isBer() {
        return this == BER;
    }

    
    /**
     * Get the EncodingOption given an integer value
     * @param value The value to translate
     * @return The associated EncodingOption
     */
    public static EncodingOption fromValue(int value) {
        switch (value) {
            case 1 : return PRIMITIVE;
            case 2 : return CONSTRUCTED;
            case 3 : return CONSTRUCTED_DEFLEN;
            case 4 : return CONSTRUCTED_INDEFLEN;
            case 5 : return IMPLICIT;
            case 6 : return EXPLICIT;
            case 7 : return BER;
            case 8 : return DER;
            case 9 : return CER;
            default : return UNKNOWN;
        }
    }
}
