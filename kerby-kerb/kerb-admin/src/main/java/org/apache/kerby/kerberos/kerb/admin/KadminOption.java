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
package org.apache.kerby.kerberos.kerb.admin;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionType;

public enum KadminOption implements KOption {
    NONE("NONE"),
    EXPIRE("-expire", "expire time", KOptionType.DATE),
    DISABLED("-disabled", "disabled", KOptionType.BOOL),
    LOCKED("-locked", "locked", KOptionType.BOOL),
    FORCE("-force", "force", KOptionType.NOV),
    KVNO("-kvno", "initial key version number", KOptionType.INT),
    PW("-pw", "password", KOptionType.STR),
    RANDKEY("-randkey", "random key", KOptionType.NOV),
    KEEPOLD("-keepold", "keep old passowrd", KOptionType.NOV),
    KEYSALTLIST("-e", "key saltlist", KOptionType.STR),
    K("-k", "keytab file path", KOptionType.STR),
    KEYTAB("-keytab", "keytab file path", KOptionType.STR),
    CCACHE("-c", "credentials cache", KOptionType.FILE);

    private String name;
    private KOptionType type = KOptionType.NONE;
    private String description;
    private Object value;

    KadminOption(String description) {
        this(description, KOptionType.NOV);
    }

    KadminOption(String description, KOptionType type) {
        this.description = description;
        this.type = type;
    }

    KadminOption(String name, String description) {
        this(name, description, KOptionType.NOV);
    }

    KadminOption(String name, String description, KOptionType type) {
        this.name = name;
        this.description = description;
        this.type = type;
    }

    public static KadminOption fromName(String name) {
        if (name != null) {
            for (KadminOption kopt : values()) {
                if (kopt.getName().equals(name)) {
                    return (KadminOption) kopt;
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
