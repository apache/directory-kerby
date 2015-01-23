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
package org.apache.kerby.kerberos.kerb.spec.ticket;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

public enum TicketFlag implements KrbEnum {
    NONE(-1),
    FORWARDABLE(0x40000000),
    FORWARDED(0x20000000),
    PROXIABLE(0x10000000),
    PROXY(0x08000000),
    MAY_POSTDATE(0x04000000),
    POSTDATED(0x02000000),
    INVALID(0x01000000),
    RENEWABLE(0x00800000),
    INITIAL(0x00400000),
    PRE_AUTH(0x00200000),
    HW_AUTH(0x00100000),
    TRANSIT_POLICY_CHECKED(  0x00080000),
    OK_AS_DELEGATE(0x00040000),
    ENC_PA_REP(0x00010000),
    ANONYMOUS(0x00008000);

    private final int value;

    private TicketFlag(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static TicketFlag fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (TicketFlag) e;
            }
        }

        return NONE;
    }
}
