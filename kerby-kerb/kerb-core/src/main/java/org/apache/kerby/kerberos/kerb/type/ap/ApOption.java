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
package org.apache.kerby.kerberos.kerb.type.ap;

import org.apache.kerby.asn1.EnumType;

/**
 * The various APOptions values, as defined in RFC 4120.
 * 
 * <pre>
 * APOptions       ::= KerberosFlags
 *         -- reserved(0),
 *         -- use-session-key(1),
 *         -- mutual-required(2)
 * </pre>
 *         
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum ApOption implements EnumType {
    NONE(-1),
    RESERVED(0x80000000),               // Bit 0, in ASN.1 BIT STRING definition : the most left-handed bit 
    USE_SESSION_KEY(0x40000000),        // Bit 1
    MUTUAL_REQUIRED(0x20000000),        // Bit 2
    //
    // The following values are taken from the MIT Kerberos file krb5.hin :
    // 
    // #define AP_OPTS_ETYPE_NEGOTIATION  0x00000002
    // #define AP_OPTS_USE_SUBKEY         0x00000001 /**< Generate a subsession key
    //                                                  from the current session key
    //                                                  obtained from the
    //                                                  credentials */
    //
    // ---->
    ETYPE_NEGOTIATION(0x00000002),      // bit 30
    USE_SUBKEY(0x00000001);             // bit 31
    // <---- End of krb5.hin inclusion

    /** The internal value */
    private final int value;

    /**
     * Create a new enum 
     */
    ApOption(int value) {
        this.value = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return name();
    }

    /**
     * Get the APOptions associated with a value.
     * 
     * @param value The integer value of the APOptions we are looking for
     * @return The associated APOptions, or NONE if not found or if value is null
     */
    public static ApOption fromValue(int value) {
        for (EnumType e : values()) {
            if (e.getValue() == value) {
                return (ApOption) e;
            }
        }

        return NONE;
    }
}
