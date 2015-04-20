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
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.util.List;

/**
 * Kerb client side configuration API.
 */
public class KrbConfig extends Conf {

    public boolean enableDebug() {
        return getBoolean(KrbConfigKey.KRB_DEBUG);
    }

    /**
     * Get KDC host name
     * @return
     */
    public String getKdcHost() {
        return getString(KrbConfigKey.KDC_HOST);
    }

    /**
     * Get KDC port, as both TCP and UDP ports
     * @return
     */
    public int getKdcPort() {
        Integer kdcPort = getInt(KrbConfigKey.KDC_PORT);
        return kdcPort.shortValue();
    }

    /**
     * Get KDC TCP port
     * @return
     */
    public int getKdcTcpPort() {
        Integer kdcPort = getInt(KrbConfigKey.KDC_TCP_PORT);
        if (kdcPort > 0) {
            return kdcPort.shortValue();
        }
        return getKdcPort();
    }

    /**
     * Is to allow UDP for KDC
     * @return true to allow UDP, false otherwise
     */
    public boolean allowKdcUdp() {
        return getBoolean(KrbConfigKey.KDC_ALLOW_UDP);
    }

    /**
     * Get KDC UDP port
     * @return
     */
    public int getKdcUdpPort() {
        Integer kdcPort = getInt(KrbConfigKey.KDC_UDP_PORT);
        if (kdcPort > 0) {
            return kdcPort.shortValue();
        }
        return getKdcPort();
    }

    public String getKdcRealm() {
        return KrbConfHelper.getStringUnderSection(this, KrbConfigKey.KDC_REALM);
    }

    public boolean isPreauthRequired() {
        return getBoolean(KrbConfigKey.PREAUTH_REQUIRED);
    }

    public String getTgsPrincipal() {
        return getString(KrbConfigKey.TGS_PRINCIPAL);
    }

    public long getAllowableClockSkew() {
        return KrbConfHelper.getLongUnderSection(this, KrbConfigKey.CLOCKSKEW);
    }

    public boolean isEmptyAddressesAllowed() {
        return getBoolean(KrbConfigKey.EMPTY_ADDRESSES_ALLOWED);
    }

    public boolean isForwardableAllowed() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.FORWARDABLE);
    }

    public boolean isPostdatedAllowed() {
        return getBoolean(KrbConfigKey.POSTDATED_ALLOWED);
    }

    public boolean isProxiableAllowed() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.PROXIABLE);
    }

    public boolean isRenewableAllowed() {
        return getBoolean(KrbConfigKey.RENEWABLE_ALLOWED);
    }

    public long getMaximumRenewableLifetime() {
        return getLong(KrbConfigKey.MAXIMUM_RENEWABLE_LIFETIME);
    }

    public long getMaximumTicketLifetime() {
        return getLong(KrbConfigKey.MAXIMUM_TICKET_LIFETIME);
    }

    public long getMinimumTicketLifetime() {
        return getLong(KrbConfigKey.MINIMUM_TICKET_LIFETIME);
    }

    public List<EncryptionType> getEncryptionTypes() {
        return KrbConfHelper.getEncTypesUnderSection(this, KrbConfigKey.PERMITTED_ENCTYPES);
    }

    public boolean isPaEncTimestampRequired() {
        return getBoolean(KrbConfigKey.PA_ENC_TIMESTAMP_REQUIRED);
    }

    public boolean isBodyChecksumVerified() {
        return getBoolean(KrbConfigKey.VERIFY_BODY_CHECKSUM);
    }

    public String getDefaultRealm() {
        return KrbConfHelper.getStringUnderSection(this, KrbConfigKey.DEFAULT_REALM);
    }

    public boolean getDnsLookUpKdc() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.DNS_LOOKUP_KDC);
    }

    public boolean getDnsLookUpRealm() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.DNS_LOOKUP_REALM);
    }

    public boolean getAllowWeakCrypto() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.ALLOW_WEAK_CRYPTO);
    }

    public long getTicketLifetime() {
        return KrbConfHelper.getLongUnderSection(this, KrbConfigKey.TICKET_LIFETIME);
    }

    public long getRenewLifetime() {
        return KrbConfHelper.getLongUnderSection(this, KrbConfigKey.RENEW_LIFETIME);
    }

    public List<EncryptionType> getDefaultTgsEnctypes() {
        return KrbConfHelper.getEncTypesUnderSection(this, KrbConfigKey.DEFAULT_TGS_ENCTYPES);
    }

    public List<EncryptionType> getDefaultTktEnctypes() {
        return KrbConfHelper.getEncTypesUnderSection(this, KrbConfigKey.DEFAULT_TKT_ENCTYPES);
    }

    public String getDefaultLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(this, KrbConfigKey.DEFAULT);
    }

    public String getKdcLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(this, KrbConfigKey.KDC);
    }

    public String getAdminLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(this, KrbConfigKey.ADMIN_SERVER);
    }


}
