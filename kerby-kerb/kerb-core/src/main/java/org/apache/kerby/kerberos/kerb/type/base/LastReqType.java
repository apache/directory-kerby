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

public enum LastReqType implements EnumType {
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

    LastReqType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    @Override
    public String getName() {
        return name();
    }

    public static LastReqType fromValue(Integer value) {
        if (value != null) {
            for (EnumType e : values()) {
                if (e.getValue() == value) {
                    return (LastReqType) e;
                }
            }
        }
        return NONE;
    }
}
