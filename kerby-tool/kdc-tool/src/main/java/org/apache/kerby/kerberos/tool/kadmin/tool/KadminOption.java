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
package org.apache.kerby.kerberos.tool.kadmin.tool;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionType;

public enum KadminOption implements KOption {
    NONE("NONE"),
    EXPIRE("-expire", "expire time", KOptionType.DATE),
    DISABLED("-disabled", "disabled", KOptionType.BOOL),
    LOCKED("-locked", "locked", KOptionType.BOOL),
    FORCE("-force", "force", KOptionType.NOV),
    ;

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
        if (name != null ) {
            for (KadminOption kopt : values()) {
                if (kopt.getName().equals(name)) {
                    return (KadminOption) kopt;
                }
            }
        }
        return NONE;
    }

    @Override
    public String getOptionName() {
        return name();
    }

    @Override
    public KOptionType getType() {
        return this.type;
    }

    @Override
    public void setType(KOptionType type) {
        this.type = type;
    }

    @Override
    public String getName() {
        if (name != null) {
            return name;
        }
        return name();
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public Object getValue() {
        return value;
    }

    @Override
    public void setValue(Object value) {
        this.value = value;
    }
}
