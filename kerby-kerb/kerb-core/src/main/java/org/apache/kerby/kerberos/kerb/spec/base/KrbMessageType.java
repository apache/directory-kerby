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
package org.apache.kerby.kerberos.kerb.spec.base;

import org.apache.kerby.asn1.type.Asn1EnumType;

public enum KrbMessageType implements Asn1EnumType {
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
    public int getIntValue() {
        return value;
    }

    public static KrbMessageType fromValue(Integer value) {
        if (value != null) {
            for (Asn1EnumType e : values()) {
                if (e.getIntValue() == value.intValue()) {
                    return (KrbMessageType) e;
                }
            }
        }

        return NONE;
    }
}
