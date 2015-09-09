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
 * A class used to hold the various encoding options for a type.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EncodingOption {
    /**
     * Encoding type
     */
    protected static enum EncodingType {
        BER,
        DER,
        CER;
    }

    private EncodingType encodingType;
    private boolean isPrimitive;
    private boolean isDefLen;
    private boolean isImplicit;

    /**
     * The default constructor with default values.
     */
    public EncodingOption() {
        this.encodingType = EncodingType.BER;
        this.isPrimitive = true;
        this.isImplicit = true;
    }

    /** 
     * A mask to determinate if a Tag is CONSTRUCTED. The fifth bit should be set to 1 if
     * the type is constructed (0010-0000).
     */
    public static final int CONSTRUCTED_FLAG = 0x20;

    public static boolean isConstructed(int tag) {
        return (tag & CONSTRUCTED_FLAG) != 0;
    }

    /**
     * Use primitive.
     */
    public void usePrimitive() {
        this.isPrimitive = true;
    }

    /**
     * Tells if the EncodingOption is PRIMITIVE
     * 
     * @return true if using PRIMITIVE, false otherwise
     */
    public boolean isPrimitive() {
        return this.isPrimitive;
    }

    /**
     * Use constructed.
     */
    public void useConstructed() {
        this.isPrimitive = false;
        useNonDefLen();
    }

    /**
     * Tells if it's constructed (not primitive).
     * 
     * @return true if it's constructed, false otherwise
     */
    public boolean isConstructed() {
        return !isPrimitive;
    }

    /**
     * Use definitive length, only makes sense when it's constructed.
     */
    public void useDefLen() {
        if (isPrimitive()) {
            throw new IllegalArgumentException("It's only for constructed");
        }
        this.isDefLen = true;
    }

    /**
     * Use non-definitive length, only makes sense when it's constructed.
     */
    public void useNonDefLen() {
        if (isPrimitive()) {
            throw new IllegalArgumentException("It's only for constructed");
        }
        this.isDefLen = false;
    }

    /**
     * Tells if it's definitive length or not.
     * @return The boolean value
     */
    public boolean isDefLen() {
        return this.isDefLen;
    }

    /**
     * Use implicit, which will discard the value set by useExplicit.
     */
    public void useImplicit() {
        this.isImplicit = true;
    }

    /**
     * Tells if it's is IMPLICIT
     * 
     * @return true if using IMPLICIT, false otherwise
     */
    public boolean isImplicit() {
        return isImplicit;
    }

    /**
     * Use explicit, which will discard the value set by useImplicit.
     */
    public void useExplicit() {
        this.isImplicit = false;
    }

    /**
     * Tells if it's is EXPLICIT
     * 
     * @return true if using EXPLICIT, false otherwise
     */
    public boolean isExplicit() {
        return !isImplicit;
    }

    /**
     * Set encoding type as DER.
     */
    public void useDer() {
        this.encodingType = EncodingType.DER;
    }

    /**
     * Tells if it's is DER
     * 
     * @return true if using DER, false otherwise
     */
    public boolean isDer() {
        return encodingType == EncodingType.DER;
    }

    /**
     * Set encoding type as BER.
     */
    public void useBer() {
        this.encodingType = EncodingType.BER;
    }

    /**
     * Tells if it's is BER
     *
     * @return true if using BER, false otherwise
     */
    public boolean isBer() {
        return encodingType == EncodingType.BER;
    }

    /**
     * Set encoding type as CER.
     */
    public void useCer() {
        this.encodingType = EncodingType.CER;
    }

    /**
     * Tells if it's is CER
     * 
     * @return true if using CER, false otherwise
     */
    public boolean isCer() {
        return encodingType == EncodingType.CER;
    }

}
