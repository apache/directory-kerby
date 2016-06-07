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
package org.apache.kerby.kerberos.kerb.admin.kadmin;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionInfo;
import org.apache.kerby.KOptionType;

public enum KadminOption implements KOption {
    NONE(null),
    EXPIRE(new KOptionInfo("-expire", "expire time", KOptionType.DATE)),
    DISABLED(new KOptionInfo("-disabled", "disabled", KOptionType.BOOL)),
    LOCKED(new KOptionInfo("-locked", "locked", KOptionType.BOOL)),
    FORCE(new KOptionInfo("-force", "force", KOptionType.NOV)),
    KVNO(new KOptionInfo("-kvno", "initial key version number", KOptionType.INT)),
    SIZE(new KOptionInfo("-size", "principal's numbers", KOptionType.STR)),
    PW(new KOptionInfo("-pw", "password", KOptionType.STR)),
    RANDKEY(new KOptionInfo("-randkey", "random key", KOptionType.NOV)),
    KEEPOLD(new KOptionInfo("-keepold", "keep old passowrd", KOptionType.NOV)),
    KEYSALTLIST(new KOptionInfo("-e", "key saltlist", KOptionType.STR)),
    K(new KOptionInfo("-k", "keytab file path", KOptionType.STR)),
    KEYTAB(new KOptionInfo("-keytab", "keytab file path", KOptionType.STR)),
    CCACHE(new KOptionInfo("-c", "credentials cache", KOptionType.FILE));

    private final KOptionInfo optionInfo;

    KadminOption(KOptionInfo optionInfo) {
        this.optionInfo = optionInfo;
    }

    @Override
    public KOptionInfo getOptionInfo() {
        return optionInfo;
    }

    public static KadminOption fromName(String name) {
        if (name != null) {
            for (KadminOption ko : values()) {
                if (ko.optionInfo != null
                        && ko.optionInfo.getName().equals(name)) {
                    return ko;
                }
            }
        }
        return NONE;
    }

    public static KadminOption fromOptionName(String optionName) {
        if (optionName != null) {
            for (KadminOption ko : values()) {
                if (ko.optionInfo != null
                    && ko.optionInfo.getName().equals(optionName)) {
                    return ko;
                }
            }
        }
        return NONE;
    }
}
