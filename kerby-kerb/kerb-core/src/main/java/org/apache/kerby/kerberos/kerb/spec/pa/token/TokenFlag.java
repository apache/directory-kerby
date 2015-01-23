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
package org.apache.kerby.kerberos.kerb.spec.pa.token;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

public enum TokenFlag implements KrbEnum {
    NONE(-1),
    ID_TOKEN_REQUIRED(0x40000000),
    AC_TOKEN_REQUIRED(0x20000000),
    BEARER_TOKEN_REQUIRED(0x10000000),
    HOK_TOKEN_REQUIRED(0x08000000);

    private final int value;

    private TokenFlag(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static TokenFlag fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (TokenFlag) e;
            }
        }

        return NONE;
    }
}
