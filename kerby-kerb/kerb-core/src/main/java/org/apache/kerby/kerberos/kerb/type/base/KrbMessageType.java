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
 * The possible Kerberos Messages :
 * 
 * <ul>
 *   <li>AS-REQ    : [APPLICATION 10]</li>
 *   <li>AS-REP    : [APPLICATION 11]</li>
 *   <li>TGS-REQ   : [APPLICATION 12]</li>
 *   <li>TGS-REP   : [APPLICATION 13]</li>
 *   <li>AP-REQ    : [APPLICATION 14]</li>
 *   <li>AP-REP    : [APPLICATION 15]</li>
 *   <li>KRB-SAFE  : [APPLICATION 20]</li>
 *   <li>KRB-PRIV  : [APPLICATION 21]</li>
 *   <li>KRB-CRED  : [APPLICATION 22]</li>
 *   <li>KRB_ERROR : [APPLICATION 30]</li>
 * </ul>
 * 
 * @author elecharny
 *
 */
public enum KrbMessageType implements EnumType {
    NONE(-1),
    AS_REQ(10),
    AS_REP(11),
    TGS_REQ(12),
    TGS_REP(13),
    AP_REQ(14),
    AP_REP(15),
    KRB_SAFE(20),
    KRB_PRIV(21),
    KRB_CRED(22),
    KRB_ERROR(30);

    /** The internal value  */
    private int value;

    /**
     * Create a new enum 
     */
    KrbMessageType(int value) {
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
     * Get the KrbMessageType associated with a value.
     * 
     * @param value The integer value of the KrbMessageType we are looking for
     * @return The associated KrbMessageType, or NONE if not found or if value is null
     */
    public static KrbMessageType fromValue(Integer value) {
        if (value != null) {
            for (EnumType e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (KrbMessageType) e;
                }
            }
        }

        return NONE;
    }
}
