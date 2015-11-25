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

public enum LastReqType implements Asn1EnumType {
    NONE(0),
    ALL_LAST_TGT(1),
    THE_LAST_TGT(-1),
    ALL_LAST_INITIAL(2),
    THE_LAST_INITIAL(-2),
    ALL_LAST_TGT_ISSUED(3),
    THE_LAST_TGT_ISSUED(-3),
    ALL_LAST_RENEWAL(4),
    THE_LAST_RENEWAL(-4),
    ALL_LAST_REQ(5),
    THE_LAST_REQ(-5),
    ALL_PW_EXPTIME(6),
    THE_PW_EXPTIME(-6),
    ALL_ACCT_EXPTIME(7),
    THE_ACCT_EXPTIME(-7);

    private int value;

    private LastReqType(int value) {
        this.value = value;
    }

    @Override
    public int getIntValue() {
        return value;
    }

    public static LastReqType fromValue(Integer value) {
        if (value != null) {
            for (Asn1EnumType e : values()) {
                if (e.getIntValue() == value) {
                    return (LastReqType) e;
                }
            }
        }
        return NONE;
    }
}
