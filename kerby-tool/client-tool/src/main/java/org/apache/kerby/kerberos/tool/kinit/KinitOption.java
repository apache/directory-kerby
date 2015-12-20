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
package org.apache.kerby.kerberos.tool.kinit;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionInfo;
import org.apache.kerby.KOptionType;
import org.apache.kerby.kerberos.kerb.client.KrbOptionGroup;

public enum KinitOption implements KOption {
    NONE(null),

    CLIENT_PRINCIPAL(new KOptionInfo("client-principal", "Client principal",
        KrbOptionGroup.KRB, KOptionType.STR)),
    LIFE_TIME(new KOptionInfo("-l", "lifetime",
        KrbOptionGroup.KRB, KOptionType.INT)),
    START_TIME(new KOptionInfo("-s", "start time",
        KrbOptionGroup.KRB, KOptionType.INT)),
    RENEWABLE_LIFE(new KOptionInfo("-r", "renewable lifetime",
        KrbOptionGroup.KRB, KOptionType.INT)),
    AS_ENTERPRISE_PN(new KOptionInfo("-E", "client is enterprise principal name",
        KrbOptionGroup.KRB)),
    INCLUDE_ADDRESSES(new KOptionInfo("-a", "include addresses",
        KrbOptionGroup.KRB)),
    NOT_INCLUDE_ADDRESSES(new KOptionInfo("-A", "do not include addresses",
        KrbOptionGroup.KRB)),

    FORWARDABLE(new KOptionInfo("-f", "forwardable",
        KrbOptionGroup.KDC_FLAGS)),
    NOT_FORWARDABLE(new KOptionInfo("-F", "not forwardable",
        KrbOptionGroup.KDC_FLAGS)),
    PROXIABLE(new KOptionInfo("-p", "proxiable",
        KrbOptionGroup.KDC_FLAGS)),
    NOT_PROXIABLE(new KOptionInfo("-P", "not proxiable",
        KrbOptionGroup.KDC_FLAGS)),
    ANONYMOUS(new KOptionInfo("-n", "anonymous",
        KrbOptionGroup.KDC_FLAGS)),
    VALIDATE(new KOptionInfo("-v", "validate",
        KrbOptionGroup.KDC_FLAGS)),
    RENEW(new KOptionInfo("-R", "renew",
        KrbOptionGroup.KDC_FLAGS)),
    CANONICALIZE(new KOptionInfo("-C", "canonicalize",
        KrbOptionGroup.KDC_FLAGS)),

    USE_PASSWD(new KOptionInfo("using password", "using password",
        KrbOptionGroup.KRB)),
    USER_PASSWD(new KOptionInfo("user-passwd", "User plain password",
        KrbOptionGroup.KRB)),
    USE_KEYTAB(new KOptionInfo("-k", "use keytab",
        KrbOptionGroup.KRB)),
    USE_DFT_KEYTAB(new KOptionInfo("-i", "use default client keytab (with -k)",
        KrbOptionGroup.KRB)),
    KEYTAB_FILE(new KOptionInfo("-t", "filename of keytab to use",
        KrbOptionGroup.KRB, KOptionType.FILE)),
    KRB5_CACHE(new KOptionInfo("-c", "Kerberos 5 cache name",
        KrbOptionGroup.KRB, KOptionType.STR)),
    SERVICE(new KOptionInfo("-S", "service",
        KrbOptionGroup.KRB, KOptionType.STR)),
    ARMOR_CACHE(new KOptionInfo("-T", "armor credential cache",
        KrbOptionGroup.KRB, KOptionType.FILE)),

    XATTR(new KOptionInfo("-X", "<attribute>[=<value>]", KOptionType.STR)),
    CONF_DIR(new KOptionInfo("-conf", "conf dir", KOptionType.DIR));

    private final KOptionInfo optionInfo;

    KinitOption(KOptionInfo optionInfo) {
        this.optionInfo = optionInfo;
    }

    @Override
    public KOptionInfo getOptionInfo() {
        return optionInfo;
    }

    public static KinitOption fromName(String name) {
        if (name != null) {
            for (KinitOption ko : values()) {
                if (ko.name().equals(name)) {
                    return ko;
                }
            }
        }
        return NONE;
    }
}

