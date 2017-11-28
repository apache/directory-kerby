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
package org.apache.kerby.has.tool.client.klist;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionInfo;
import org.apache.kerby.KOptionType;

public enum KlistOption implements KOption {
    NONE(null),
    CREDENTIALS_CACHE(new KOptionInfo("-c", "specifies path of credentials cache",
        KOptionType.STR)),
    KEYTAB(new KOptionInfo("-k", "specifies keytab")),
    DEFAULT_CLIENT_KEYTAB(new KOptionInfo("-i", "uses default client keytab if no name given")),
    LIST_CREDENTIAL_CACHES(new KOptionInfo("-l", "list credential caches in collection")),
    ALL_CREDENTIAL_CACHES(new KOptionInfo("-A", "shows content of all credential caches")),
    ENCRYPTION_TYPE(new KOptionInfo("-e", "shows encryption type")),
    KERBEROS_VERSION(new KOptionInfo("-V", "shows Kerberos version")),
    AUTHORIZATION_DATA_TYPE(new KOptionInfo("-d", "shows the submitted authorization data type")),
    CREDENTIALS_FLAGS(new KOptionInfo("-f", "show credential flags")),
    EXIT_TGT_EXISTENCE(new KOptionInfo("-s", "sets exit status based on valid tgt existence")),
    DISPL_ADDRESS_LIST(new KOptionInfo("-a", "displays the address list")),
    NO_REVERSE_RESOLVE(new KOptionInfo("-n", "do not reverse resolve")),
    SHOW_KTAB_ENTRY_TS(new KOptionInfo("-t", "shows keytab entry timestamps")),
    SHOW_KTAB_ENTRY_KEY(new KOptionInfo("-K", "show keytab entry keys"));

    private final KOptionInfo optionInfo;

    KlistOption(KOptionInfo optionInfo) {
        this.optionInfo = optionInfo;
    }

    @Override
    public KOptionInfo getOptionInfo() {
        return optionInfo;
    }

    public static KlistOption fromName(String name) {
        if (name != null) {
            for (KlistOption ko : values()) {
                if (ko.optionInfo != null
                        && ko.optionInfo.getName().equals(name)) {
                    return ko;
                }
            }
        }
        return NONE;
    }
}
