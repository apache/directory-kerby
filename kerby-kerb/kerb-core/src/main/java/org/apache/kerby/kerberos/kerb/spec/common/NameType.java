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

public enum NameType implements KrbEnum {
    NT_UNKNOWN(0),
    NT_PRINCIPAL(1),
    NT_SRV_INST(2),
    NT_SRV_HST(3),
    NT_SRV_XHST(4),
    NT_UID(5);
    
    private int value;

    private NameType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static NameType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (NameType) e;
                }
            }
        }

        return NT_UNKNOWN;
    }
}
