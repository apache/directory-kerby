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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.config.ConfigKey;

public enum KrbConfigKey implements ConfigKey {
    KRB_DEBUG(true),
    KDC_HOST("localhost"),
    KDC_PORT(null),
    KDC_ALLOW_UDP(false),
    KDC_ALLOW_TCP(false),
    KDC_UDP_PORT(null),
    KDC_TCP_PORT(null),
    KDC_DOMAIN("example.com"),
    KDC_REALM("EXAMPLE.COM"),
    TGS_PRINCIPAL("krbtgt@EXAMPLE.COM"),
    PREAUTH_REQUIRED(true),
    CLOCKSKEW(5 * 60L),
    EMPTY_ADDRESSES_ALLOWED(true),
    PA_ENC_TIMESTAMP_REQUIRED(true),
    MAXIMUM_TICKET_LIFETIME(24 * 3600L),
    MINIMUM_TICKET_LIFETIME(1 * 3600L),
    MAXIMUM_RENEWABLE_LIFETIME(48 * 3600L),
    FORWARDABLE(true),
    POSTDATED_ALLOWED(true),
    PROXIABLE(true),
    RENEWABLE_ALLOWED(true),
    VERIFY_BODY_CHECKSUM(true),
    PERMITTED_ENCTYPES("aes128-cts-hmac-sha1-96"),
    DEFAULT_REALM(null),
    DNS_LOOKUP_KDC(false),
    DNS_LOOKUP_REALM(false),
    ALLOW_WEAK_CRYPTO(true),
    TICKET_LIFETIME(24 * 3600L),
    RENEW_LIFETIME(48 * 3600L),
    DEFAULT_TGS_ENCTYPES("aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 "
            + "des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac "
            + "camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4"),
    DEFAULT_TKT_ENCTYPES("aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 "
            + "des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac "
            + "camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4"),

    PKINIT_ANCHORS(null),
    PKINIT_IDENTITIES(null),
    PKINIT_KDC_HOSTNAME();

    private Object defaultValue;

    KrbConfigKey() {
        this.defaultValue = null;
    }

    KrbConfigKey(Object defaultValue) {
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
