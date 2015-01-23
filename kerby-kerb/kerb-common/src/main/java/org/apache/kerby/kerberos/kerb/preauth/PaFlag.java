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
package org.apache.kerby.kerberos.kerb.preauth;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

public enum PaFlag implements KrbEnum {
    NONE(-1),
    PA_REAL(0x01),
    PA_INFO(0x02);

    private final int value;

    private PaFlag(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static PaFlag fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (PaFlag) e;
            }
        }

        return NONE;
    }
}
