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
package org.apache.kerby.kerberos.tool.klist;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionType;

public enum KlistOption implements KOption {
    NONE("NONE"),
    CREDENTIALS_CACHE("-c", "specifies path of credentials cache", KOptionType.STR),
    KEYTAB("-k", "specifies keytab"),
    DEFAULT_CLIENT_KEYTAB("-i", "uses default client keytab if no name given"),
    LIST_CREDENTIAL_CACHES("-l", "list credential caches in collection"),
    ALL_CREDENTIAL_CACHES("-A", "shows content of all credential caches"),
    ENCRYPTION_TYPE("-e", "shows encryption type"),
    KERBEROS_VERSION("-V", "shows Kerberos version"),
    AUTHORIZATION_DATA_TYPE("-d", "shows the submitted authorization data type"),
    CREDENTIALS_FLAGS("-f", "show credential flags"),
    EXIT_TGT_EXISTENCE("-s", "sets exit status based on valid tgt existence"),
    DISPL_ADDRESS_LIST("-a", "displays the address list"),
    NO_REVERSE_RESOLVE("-n", "do not reverse resolve"),
    SHOW_KTAB_ENTRY_TS("-t", "shows keytab entry timestamps"),
    SHOW_KTAB_ENTRY_KEY("-K", "show keytab entry keys");

    private String name;
    private KOptionType type = KOptionType.NONE;
    private String description;
    private Object value;

    KlistOption(String description) {
        this(description, KOptionType.NOV);
    }

    KlistOption(String description, KOptionType type) {
        this.description = description;
        this.type = type;
    }

    KlistOption(String name, String description) {
        this(name, description, KOptionType.NOV);
    }

    KlistOption(String name, String description, KOptionType type) {
        this.name = name;
        this.description = description;
        this.type = type;
    }

    public static KlistOption fromName(String name) {
        if (name != null) {
            for (KlistOption klopt : values()) {
                if (klopt.getName().equals(name)) {
                    return (KlistOption) klopt;
                }
            }
        }
        return NONE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getOptionName() {
        return name();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KOptionType getType() {
        return this.type;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setType(KOptionType type) {
        this.type = type;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        if (name != null) {
            return name;
        }
        return name();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setName(String name) {
        this.name = name;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getDescription() {
        return this.description;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setValue(Object value) {
        this.value = value;
    }

}
