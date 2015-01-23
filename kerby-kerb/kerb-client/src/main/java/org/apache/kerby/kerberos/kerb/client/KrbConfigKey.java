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

import org.apache.kerby.kerberos.kerb.common.SectionConfigKey;

public enum KrbConfigKey implements SectionConfigKey {
    KRB_DEBUG(true),
    KDC_HOST("localhost"),
    KDC_PORT(8015),
    KDC_DOMAIN("example.com"),
    KDC_REALM("EXAMPLE.COM"),
    TGS_PRINCIPAL("krbtgt@EXAMPLE.COM"),
    PREAUTH_REQUIRED(true),
    CLOCKSKEW(5 * 60L, "libdefaults"),
    EMPTY_ADDRESSES_ALLOWED(true),
    PA_ENC_TIMESTAMP_REQUIRED(true),
    MAXIMUM_TICKET_LIFETIME(24 * 3600L),
    MINIMUM_TICKET_LIFETIME(1 * 3600L),
    MAXIMUM_RENEWABLE_LIFETIME(48 * 3600L),
    FORWARDABLE(true, "libdefaults"),
    POSTDATED_ALLOWED(true),
    PROXIABLE(true, "libdefaults"),
    RENEWABLE_ALLOWED(true),
    VERIFY_BODY_CHECKSUM(true),
    PERMITTED_ENCTYPES("aes128-cts-hmac-sha1-96", "libdefaults"),
    DEFAULT_REALM("EXAMPLE.COM", "libdefaults"),
    DNS_LOOKUP_KDC(false, "libdefaults"),
    DNS_LOOKUP_REALM(false, "libdefaults"),
    ALLOW_WEAK_CRYPTO(true, "libdefaults"),
    TICKET_LIFETIME(24 * 3600L, "libdefaults"),
    RENEW_LIFETIME(48 * 3600L, "libdefaults"),
    DEFAULT_TGS_ENCTYPES("aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 " +
        "des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac " +
        "camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4",
        "libdefaults"),
    DEFAULT_TKT_ENCTYPES("aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 " +
        "des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac " +
        "camellia128-cts-cmac des-cbc-crc des-cbc-md5 des-cbc-md4",
        "libdefaults"),

    //key for logging location
    DEFAULT(null, "logging"),
    KDC(null, "logging"),
    ADMIN_SERVER(null, "logging");

    private Object defaultValue;
    /**
     * The name of a section where a config key is contained in MIT Kerberos config file.
     */
    private String sectionName;

    private KrbConfigKey() {
        this.defaultValue = null;
    }

    private KrbConfigKey(Object defaultValue) {
        this.defaultValue = defaultValue;
    }

    private KrbConfigKey(Object defaultValue, String sectionName) {
        this(defaultValue);
        this.sectionName = sectionName;
    }

    /**
     * Use the propertyKey, we can get the configuration value from Object Conf.
     */
    @Override
    public String getPropertyKey() {
        return name().toLowerCase();
    }

    @Override
    public Object getDefaultValue() {
        return this.defaultValue;
    }

    @Override
    public String getSectionName() {
        return sectionName;
    }
}
