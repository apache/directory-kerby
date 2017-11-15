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
package org.apache.hadoop.has.common;

import org.apache.kerby.config.ConfigKey;

public enum HasConfigKey implements ConfigKey {
    HTTP_HOST,
    HTTP_PORT,
    HTTPS_HOST,
    HTTPS_PORT,
    AUTH_TYPE("RAM"),
    REALM,
    ENABLE_CONF,
    SSL_SERVER_CONF("/etc/has/ssl-server.conf"),
    SSL_CLIENT_CONF("/etc/has/ssl-client.conf"),
    SSL_CLIENT_CERT("/etc/has/cert-signed"),
    FILTER_AUTH_TYPE("kerberos"),
    KERBEROS_PRINCIPAL,
    KERBEROS_KEYTAB,
    KERBEROS_NAME_RULES,
    ADMIN_KEYTAB,
    ADMIN_KEYTAB_PRINCIPAL;

    private Object defaultValue;

    HasConfigKey() {
        this.defaultValue = null;
    }

    HasConfigKey(Object defaultValue) {
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
