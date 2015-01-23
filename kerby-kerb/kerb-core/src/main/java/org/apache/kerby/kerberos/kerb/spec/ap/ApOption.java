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
package org.apache.kerby.kerberos.kerb.spec.ap;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

/**
 APOptions       ::= KrbFlags
 -- reserved(0),
 -- use-session-key(1),
 -- mutual-required(2)
 */
public enum ApOption implements KrbEnum {
    NONE(-1),
    RESERVED(0x80000000),
    USE_SESSION_KEY(0x40000000),
    MUTUAL_REQUIRED(0x20000000),
    ETYPE_NEGOTIATION(0x00000002),
    USE_SUBKEY(0x00000001);

    private final int value;

    private ApOption(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static ApOption fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (ApOption) e;
            }
        }

        return NONE;
    }
}