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
package org.apache.kerby.kerberos.kerb.spec.common;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

public enum SamType implements KrbEnum
{
    SAM_NONE(0),
    /** safe SAM type enum for Enigma Logic */
    SAM_TYPE_ENIGMA(1), // Enigma Logic"

    /** safe SAM type enum for Digital Pathways */
    SAM_TYPE_DIGI_PATH(2), // Digital Pathways

    /** safe SAM type enum for S/key where KDC has key 0 */
    SAM_TYPE_SKEY_K0(3), // S/key where KDC has key 0

    /** safe SAM type enum for Traditional S/Key */
    SAM_TYPE_SKEY(4), // Traditional S/Key

    /** safe SAM type enum for Security Dynamics */
    SAM_TYPE_SECURID(5), // Security Dynamics

    /** safe SAM type enum for CRYPTOCard */
    SAM_TYPE_CRYPTOCARD(6); // CRYPTOCard

    private int value;

    private SamType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static SamType fromValue(Integer value) {
        if (value != null) {
            for (SamType st : SamType.values() ) {
                if (value == st.getValue()) {
                    return st;
                }
            }
        }
        return SAM_NONE;
    }
}
