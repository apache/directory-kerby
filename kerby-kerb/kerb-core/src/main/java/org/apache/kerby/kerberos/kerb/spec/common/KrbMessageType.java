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

public enum KrbMessageType implements KrbEnum {
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

    private int value;

    private KrbMessageType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static KrbMessageType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (KrbMessageType) e;
                }
            }
        }

        return NONE;
    }
}
