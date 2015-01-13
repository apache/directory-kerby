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
package org.apache.kerberos.kerb.server;

import org.apache.haox.config.ConfigKey;

public enum KdcConfigKey implements ConfigKey {
    KRB_DEBUG(true),
    WORK_DIR,
    KDC_SERVICE_NAME("Haox_KDC_Server"),
    KDC_HOST("127.0.0.1"),
    KDC_PORT(8015),
    KDC_DOMAIN("example.com"),
    KDC_REALM("EXAMPLE.COM"),
    TGS_PRINCIPAL("krbtgt@EXAMPLE.COM"),
    PREAUTH_REQUIRED(true),
    ALLOWABLE_CLOCKSKEW(5 * 60L),
    EMPTY_ADDRESSES_ALLOWED(true),
    PA_ENC_TIMESTAMP_REQUIRED(true),
    MAXIMUM_TICKET_LIFETIME(24 * 3600L),
    MINIMUM_TICKET_LIFETIME(1 * 3600L),
    MAXIMUM_RENEWABLE_LIFETIME(48 * 3600L),
    FORWARDABLE_ALLOWED(true),
    POSTDATED_ALLOWED(true),
    PROXIABLE_ALLOWED(true),
    RENEWABLE_ALLOWED(true),
    VERIFY_BODY_CHECKSUM(true),
    ENCRYPTION_TYPES(new String[] { "aes128-cts-hmac-sha1-96", "des3-cbc-sha1-kd" });

    private Object defaultValue;

    private KdcConfigKey() {
        this.defaultValue = null;
    }

    private KdcConfigKey(Object defaultValue) {
        this.defaultValue = defaultValue;
    }

    @Override
    public String getPropertyKey() {
        return "kdc." + name().toLowerCase();
    }

    @Override
    public Object getDefaultValue() {
        return this.defaultValue;
    }
}
