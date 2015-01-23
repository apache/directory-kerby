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

import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kerb.common.KrbConfHelper;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;

import java.util.List;

public class KrbConfig {
    protected Conf conf;

    public KrbConfig() {
        this.conf = new Conf();
    }

    public Conf getConf() {
        return this.conf;
    }

    public boolean enableDebug() {
        return conf.getBoolean(KrbConfigKey.KRB_DEBUG);
    }

    public String getKdcHost() {
        return conf.getString(KrbConfigKey.KDC_HOST);
    }

    public short getKdcPort() {
        Integer kdcPort = conf.getInt(KrbConfigKey.KDC_PORT);
        return kdcPort.shortValue();
    }

    public String getKdcRealm() {
        return conf.getString(KrbConfigKey.KDC_REALM);
    }

    public String getKdcDomain() {
        return conf.getString(KrbConfigKey.KDC_DOMAIN);
    }

    public boolean isPreauthRequired() {
        return conf.getBoolean(KrbConfigKey.PREAUTH_REQUIRED);
    }

    public String getTgsPrincipal() {
        return conf.getString(KrbConfigKey.TGS_PRINCIPAL);
    }

    public long getAllowableClockSkew() {
        return KrbConfHelper.getLongUnderSection(conf, KrbConfigKey.CLOCKSKEW);
    }

    public boolean isEmptyAddressesAllowed() {
        return conf.getBoolean(KrbConfigKey.EMPTY_ADDRESSES_ALLOWED);
    }

    public boolean isForwardableAllowed() {
        return KrbConfHelper.getBooleanUnderSection(conf, KrbConfigKey.FORWARDABLE);
    }

    public boolean isPostdatedAllowed() {
        return conf.getBoolean(KrbConfigKey.POSTDATED_ALLOWED);
    }

    public boolean isProxiableAllowed() {
        return KrbConfHelper.getBooleanUnderSection(conf, KrbConfigKey.PROXIABLE);
    }

    public boolean isRenewableAllowed() {
        return conf.getBoolean(KrbConfigKey.RENEWABLE_ALLOWED);
    }

    public long getMaximumRenewableLifetime() {
        return conf.getLong(KrbConfigKey.MAXIMUM_RENEWABLE_LIFETIME);
    }

    public long getMaximumTicketLifetime() {
        return conf.getLong(KrbConfigKey.MAXIMUM_TICKET_LIFETIME);
    }

    public long getMinimumTicketLifetime() {
        return conf.getLong(KrbConfigKey.MINIMUM_TICKET_LIFETIME);
    }

    public List<EncryptionType> getEncryptionTypes() {
        return KrbConfHelper.getEncTypesUnderSection(conf, KrbConfigKey.PERMITTED_ENCTYPES);
    }

    public boolean isPaEncTimestampRequired() {
        return conf.getBoolean(KrbConfigKey.PA_ENC_TIMESTAMP_REQUIRED);
    }

    public boolean isBodyChecksumVerified() {
        return conf.getBoolean(KrbConfigKey.VERIFY_BODY_CHECKSUM);
    }

    public String getDefaultRealm() {
        return KrbConfHelper.getStringUnderSection(conf, KrbConfigKey.DEFAULT_REALM);
    }

    public boolean getDnsLookUpKdc() {
        return KrbConfHelper.getBooleanUnderSection(conf, KrbConfigKey.DNS_LOOKUP_KDC);
    }

    public boolean getDnsLookUpRealm() {
        return KrbConfHelper.getBooleanUnderSection(conf, KrbConfigKey.DNS_LOOKUP_REALM);
    }

    public boolean getAllowWeakCrypto() {
        return KrbConfHelper.getBooleanUnderSection(conf, KrbConfigKey.ALLOW_WEAK_CRYPTO);
    }

    public long getTicketLifetime() {
        return KrbConfHelper.getLongUnderSection(conf, KrbConfigKey.TICKET_LIFETIME);
    }

    public long getRenewLifetime() {
        return KrbConfHelper.getLongUnderSection(conf, KrbConfigKey.RENEW_LIFETIME);
    }

    public List<EncryptionType> getDefaultTgsEnctypes() {
        return KrbConfHelper.getEncTypesUnderSection(conf, KrbConfigKey.DEFAULT_TGS_ENCTYPES);
    }

    public List<EncryptionType> getDefaultTktEnctypes() {
        return KrbConfHelper.getEncTypesUnderSection(conf, KrbConfigKey.DEFAULT_TKT_ENCTYPES);
    }

    public String getDefaultLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(conf, KrbConfigKey.DEFAULT);
    }

    public String getKdcLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(conf, KrbConfigKey.KDC);
    }

    public String getAdminLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(conf, KrbConfigKey.ADMIN_SERVER);
    }


}
