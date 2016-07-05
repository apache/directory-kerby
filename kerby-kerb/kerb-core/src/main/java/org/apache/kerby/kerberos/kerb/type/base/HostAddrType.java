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
 * The various possible HostAddress types.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum HostAddrType implements EnumType {
    /**
     * Constant for the "null" host address type.
     */
    NONE(0),

    /**
     * Constant for the "Internet" host address type.
     */
    ADDRTYPE_INET(2),

    /**
     * Constant for the "Arpanet" host address type.
     */
    ADDRTYPE_IMPLINK(3),

    /**
     * Constant for the "CHAOS" host address type.
     */
    ADDRTYPE_CHAOS(5),

    /**
     * Constant for the "XEROX Network Services" host address type.
     */
    ADDRTYPE_XNS(6),

    /**
     * Constant for the "OSI" host address type.
     */
    ADDRTYPE_OSI(7),

    /**
     * Constant for the "DECnet" host address type.
     */
    ADDRTYPE_DECNET(12),

    /**
     * Constant for the "AppleTalk" host address type.
     */
    ADDRTYPE_APPLETALK(16),

    /**
     * Constant for the "NetBios" host address type.
     *
     * Not in RFC
     */
    ADDRTYPE_NETBIOS(20),

    /**
     * Constant for the "Internet Protocol V6" host address type.
     */
    ADDRTYPE_INET6(24);

    /** the inner value */
    private final int value;

    /**
     * Create a new enum instance
     */
    HostAddrType(int value) {
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
     * Get the HostAddrType associated with a value.
     * 
     * @param value The integer value of the HostAddrType we are looking for
     * @return The associated HostAddrType, or NULL if not found or if value is null
     */
    public static HostAddrType fromValue(Integer value) {
        if (value != null) {
            for (EnumType e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (HostAddrType) e;
                }
            }
        }

        return HostAddrType.NONE;
    }
}
