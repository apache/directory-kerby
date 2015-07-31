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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.KOption;
import org.apache.kerby.KOptionType;

/**
 * KDC server startup options
 */
public enum KdcServerOption implements KOption {
    NONE("NONE"),
    INNER_KDC_IMPL("inner KDC impl", KOptionType.OBJ),
    KDC_REALM("kdc realm", KOptionType.STR),
    KDC_HOST("kdc host", KOptionType.STR),
    KDC_PORT("kdc port", KOptionType.INT),
    ALLOW_TCP("allow tcp", KOptionType.BOOL),
    KDC_TCP_PORT("kdc tcp port", KOptionType.INT),
    ALLOW_UDP("allow udp", KOptionType.BOOL),
    KDC_UDP_PORT("kdc udp port", KOptionType.INT),
    WORK_DIR("work dir", KOptionType.DIR),
    ENABLE_DEBUG("enable debug", KOptionType.BOOL);

    private String name;
    private KOptionType type;
    private String description;
    private Object value;

    KdcServerOption(String description) {
        this(description, KOptionType.NOV); // As a flag by default
    }

    KdcServerOption(String description, KOptionType type) {
        this.description = description;
        this.type = type;
    }

    KdcServerOption(String name, String description) {
        this(name, description, KOptionType.NOV); // As a flag by default
    }

    KdcServerOption(String name, String description, KOptionType type) {
        this.name = name;
        this.description = description;
        this.type = type;
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
    public void setType(KOptionType type) {
        this.type = type;
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
    public void setName(String name) {
        this.name = name;
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
    public String getDescription() {
        return this.description;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setValue(Object value) {
        this.value = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object getValue() {
        return value;
    }

    public static KdcServerOption fromName(String name) {
        if (name != null) {
            for (KdcServerOption ko : values()) {
                if (ko.getName().equals(name)) {
                    return (KdcServerOption) ko;
                }
            }
        }
        return NONE;
    }

    public static KdcServerOption fromOptionName(String optionName) {
        if (optionName != null) {
            for (KdcServerOption ko : values()) {
                if (ko.getOptionName().equals(optionName)) {
                    return (KdcServerOption) ko;
                }
            }
        }
        return NONE;
    }
}
