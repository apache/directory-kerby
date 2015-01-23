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

// Optimized by Emmanuel
public enum UniversalTag {
    UNKNOWN             (-1),
    CHOICE              (-2), // Only for internal using
    BOOLEAN             (0x01),
    INTEGER             (0x02),
    BIT_STRING          (0x03),
    OCTET_STRING        (0x04),
    NULL                (0x05),
    OBJECT_IDENTIFIER   (0x06),
    OBJECT_DESCRIPTOR   (0x07),     // Added for completness
    EXTERNAL            (0x08),
    REAL                (0x09),
    ENUMERATED          (0x0a),
    EMBEDDED_PDV        (0x0b),     // Added for completness
    UTF8_STRING         (0x0c),
    RELATIVE_OID        (0x0d),     // Added for completness
    RESERVED_14         (0x0e),     // Added for completness
    RESERVED_15         (0x0f),     // Added for completness
    SEQUENCE            (0x10),
    SEQUENCE_OF         (0x10),
    SET                 (0x11),
    SET_OF              (0x11),
    NUMERIC_STRING      (0x12),
    PRINTABLE_STRING    (0x13),
    T61_STRING          (0x14),
    VIDEOTEX_STRING     (0x15),
    IA5_STRING          (0x16),
    UTC_TIME            (0x17),
    GENERALIZED_TIME    (0x18),
    GRAPHIC_STRING      (0x19),
    VISIBLE_STRING      (0x1a),
    GENERAL_STRING      (0x1b),
    UNIVERSAL_STRING    (0x1c),
    CHARACTER_STRING    (0x1d),     // Added for completness
    BMP_STRING          (0x1e),
    RESERVED_31         (0x1f);     // Added for completness

    private int value;

    private UniversalTag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static UniversalTag fromValue(int value) {
        switch (value) {
            case 0x01 : return BOOLEAN;
            case 0x02 : return INTEGER;
            case 0x03 : return BIT_STRING;
            case 0x04 : return OCTET_STRING;
            case 0x05 : return NULL;
            case 0x06 : return OBJECT_IDENTIFIER;
            case 0x07 : return OBJECT_DESCRIPTOR;
            case 0x08 : return EXTERNAL;
            case 0x09 : return REAL;
            case 0x0A : return ENUMERATED;
            case 0x0B : return EMBEDDED_PDV;
            case 0x0C : return UTF8_STRING;
            case 0x0D : return RELATIVE_OID;
            case 0x0E : return RESERVED_14;
            case 0x0F : return RESERVED_15;
            case 0x10 : return SEQUENCE;
            case 0x11 : return SET;
            case 0x12 : return NUMERIC_STRING;
            case 0x13 : return PRINTABLE_STRING;
            case 0x14 : return T61_STRING;
            case 0x15 : return VIDEOTEX_STRING;
            case 0x16 : return IA5_STRING;
            case 0x17 : return UTC_TIME;
            case 0x18 : return GENERALIZED_TIME;
            case 0x19 : return GRAPHIC_STRING;
            case 0x1A : return VISIBLE_STRING;
            case 0x1B : return GENERAL_STRING;
            case 0x1C : return UNIVERSAL_STRING;
            case 0x1D : return CHARACTER_STRING;
            case 0x1E : return BMP_STRING;
            case 0x1F : return RESERVED_31;
            default : return UNKNOWN;
        }
    }
}
