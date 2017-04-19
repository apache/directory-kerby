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
package org.apache.kerby.kerberos.kdc.identitybackend;

import org.apache.kerby.config.ConfigKey;

/**
 * Define all the ZK backend related configuration items with default values.
 */
public enum ZKConfKey implements ConfigKey {
    EMBEDDED_ZK(true),
    ZK_HOST("127.0.0.1"),
    ZK_PORT(2180),
    DATA_DIR("/tmp/kerby/zookeeper/data");

    private Object defaultValue;

    ZKConfKey() {
        this.defaultValue = null;
    }

    ZKConfKey(Object defaultValue) {
        this.defaultValue = defaultValue;
    }

    @Override
    public String getPropertyKey() {
        return name().toLowerCase();
    }

    @Override
    public Object getDefaultValue() {
        return this.defaultValue;
    }
}
