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
package org.apache.kerby.kerberos.kerb.type.base;

import org.apache.kerby.asn1.EnumType;

/**
 * The various PrincipalName name-type values, as defined in RFC 4120 and 61111.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum NameType implements EnumType {
    NT_UNKNOWN(0),        // Name type not known (RFC 4120)
    NT_PRINCIPAL(1),      // Just the name of the principal as in DCE, or for users (RFC 4120)
    NT_SRV_INST(2),       // Service and other unique instance (krbtgt) (RFC 4120)
    NT_SRV_HST(3),        // Service with host name as instance (telnet, rcommands) (RFC 4120)
    NT_SRV_XHST(4),       // Service with host as remaining components (RFC 4120)
    NT_UID(5),            // Unique ID (RFC 4120)
    NT_X500_PRINCIPAL(6), // Encoded X.509 Distinguished name (RFC 2253)
    NT_SMTP_NAME(7),      // Name in form of SMTP email name (e.g., user@example.com) (RFC 4120)
    NT_ENTERPRISE(10),    // Enterprise name - may be mapped to principal name (RFC 4120)
    NT_WELLKNOWN(11);     // Well-known principal names (RFC 6111)
    
    /** The internal value */
    private int value;

    /**
     * Create a new enum 
     */
    NameType(int value) {
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
     * Get the NameType associated with a value.
     * 
     * @param value The integer value of the NameType we are looking for
     * @return The associated NameType, or NT_UNKNOWN if not found or if value is null
     */
    public static NameType fromValue(Integer value) {
        if (value != null) {
            for (NameType nameType : values()) {
                if (nameType.getValue() == value) {
                    return nameType;
                }
            }
        }

        return NT_UNKNOWN;
    }
}
