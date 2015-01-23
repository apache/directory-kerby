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

public enum TagClass {
    UNKNOWN(-1),
    UNIVERSAL(0x00),
    APPLICATION(0x40),
    CONTEXT_SPECIFIC(0x80),
    PRIVATE(0xC0);

    private int value;

    private TagClass(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public boolean isUniversal() {
        return this == UNIVERSAL;
    }

    public boolean isAppSpecific() {
        return this == APPLICATION;
    }

    public boolean isContextSpecific() {
        return this == CONTEXT_SPECIFIC;
    }

    public boolean isTagged() {
        return this == APPLICATION || this == CONTEXT_SPECIFIC;
    }

    public static TagClass fromValue(int value) {
        // Optimized by Emmanuel
        switch (value) {
            case 0x00:
                return TagClass.UNIVERSAL;
            case 0x40:
                return TagClass.APPLICATION;
            case 0x80:
                return TagClass.CONTEXT_SPECIFIC;
            case 0xC0:
                return TagClass.PRIVATE;
            default:
                return TagClass.UNKNOWN;
        }
    }

    public static TagClass fromTagFlags(int tag) {
        return fromValue(tag & 0xC0);
    }
}
