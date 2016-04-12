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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin;

import org.apache.kerby.config.ConfigKey;

public enum AdminServerConfigKey implements ConfigKey {
    KRB_DEBUG(true),
    ADMIN_SERVICE_NAME("Kadmin-Server"),
    KDC_IDENTITY_BACKEND,
    ADMIN_HOST("127.0.0.1"),
    ADMIN_PORT,
    ADMIN_ALLOW_TCP(true),
    ADMIN_ALLOW_UDP(true),
    ADMIN_UDP_PORT,
    ADMIN_TCP_PORT,
    ADMIN_DOMAIN("example.com"),
    ADMIN_REALM("EXAMPLE.COM");

    private Object defaultValue;

    AdminServerConfigKey() {
        this.defaultValue = null;
    }

    AdminServerConfigKey(Object defaultValue) {
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
