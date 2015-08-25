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
     *
     * @return The kdc host
     */
    public String getKdcHost() {
        return getString(KrbConfigKey.KDC_HOST);
    }

    /**
     * Get KDC port, as both TCP and UDP ports
     *
     * @return The kdc host
     */
    public int getKdcPort() {
        Integer kdcPort = KrbConfHelper.getIntUnderSection(this,
                KrbConfigKey.KDC_PORT);
        if (kdcPort != null) {
            return kdcPort.intValue();
        }
        return -1;
    }

    /**
     * Get KDC TCP port
     *
     * @return The kdc tcp port
     */
    public int getKdcTcpPort() {
        Integer kdcPort = KrbConfHelper.getIntUnderSection(this,
                KrbConfigKey.KDC_TCP_PORT);
        if (kdcPort != null && kdcPort > 0) {
            return kdcPort.intValue();
        }
        return getKdcPort();
    }

    /**
     * Is to allow UDP for KDC
     *
     * @return true to allow UDP, false otherwise
     */
    public boolean allowKdcUdp() {
        return getBoolean(KrbConfigKey.KDC_ALLOW_UDP) || KrbConfHelper.getIntUnderSection(this,
                KrbConfigKey.KDC_UDP_PORT) != null;
    }

    /**
     * Is to allow TCP for KDC
     *
     * @return true to allow TCP, false otherwise
     */
    public boolean allowKdcTcp() {
        return getBoolean(KrbConfigKey.KDC_ALLOW_TCP) || KrbConfHelper.getIntUnderSection(this,
                KrbConfigKey.KDC_TCP_PORT) != null;
    }

    /**
     * Get KDC UDP port
     *
     * @return The kdc udp port
     */
    public int getKdcUdpPort() {
        Integer kdcPort = KrbConfHelper.getIntUnderSection(this,
                KrbConfigKey.KDC_UDP_PORT);
        if (kdcPort != null && kdcPort > 0) {
            return kdcPort.intValue();
        }
        return getKdcPort();
    }

    /**
     * Get KDC realm.
     * @return The kdc realm
     */
    public String getKdcRealm() {
        return KrbConfHelper.getStringUnderSection(this, KrbConfigKey.KDC_REALM);
    }

    /**
     * Get whether preatuh is required.
     * @return true if preauth required
     */
    public boolean isPreauthRequired() {
        return getBoolean(KrbConfigKey.PREAUTH_REQUIRED);
    }

    /**
     * Get tgs principal.
     * @return The tgs principal
     */
    public String getTgsPrincipal() {
        return getString(KrbConfigKey.TGS_PRINCIPAL);
    }

    /**
     * Get allowable clock skew.
     * @return The allowable clock skew
     */
    public long getAllowableClockSkew() {
        return KrbConfHelper.getLongUnderSection(this, KrbConfigKey.CLOCKSKEW);
    }

    /**
     * Get whether empty addresses allowed.
     * @return true if empty address is allowed
     */
    public boolean isEmptyAddressesAllowed() {
        return getBoolean(KrbConfigKey.EMPTY_ADDRESSES_ALLOWED);
    }

    /**
     * Get whether forward is allowed.
     * @return true if forward is allowed
     */
    public boolean isForwardableAllowed() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.FORWARDABLE);
    }

    /**
     * Get whether post dated is allowed.
     * @return true if post dated is allowed
     */
    public boolean isPostdatedAllowed() {
        return getBoolean(KrbConfigKey.POSTDATED_ALLOWED);
    }

    /**
     * Get whether proxy is allowed.
     * @return true if proxy is allowed
     */
    public boolean isProxiableAllowed() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.PROXIABLE);
    }

    /**
     * Get whether renew is allowed.
     * @return true if renew is allowed
     */
    public boolean isRenewableAllowed() {
        return getBoolean(KrbConfigKey.RENEWABLE_ALLOWED);
    }

    /**
     * Get maximum renewable life time.
     * @return The maximum renewable life time
     */
    public long getMaximumRenewableLifetime() {
        return getLong(KrbConfigKey.MAXIMUM_RENEWABLE_LIFETIME);
    }

    /**
     * Get maximum ticket life time.
     * @return The maximum ticket life time
     */
    public long getMaximumTicketLifetime() {
        return getLong(KrbConfigKey.MAXIMUM_TICKET_LIFETIME);
    }

    /**
     * Get minimum ticket life time.
     * @return The minimum ticket life time
     */
    public long getMinimumTicketLifetime() {
        return getLong(KrbConfigKey.MINIMUM_TICKET_LIFETIME);
    }

    /**
     * Get encryption types.
     * @return encryption type list
     */
    public List<EncryptionType> getEncryptionTypes() {
        return KrbConfHelper.getEncTypesUnderSection(this, KrbConfigKey.PERMITTED_ENCTYPES);
    }

    /**
     * Get whether pa encrypt timestamp required.
     * @return true if pa encrypt time required
     */
    public boolean isPaEncTimestampRequired() {
        return getBoolean(KrbConfigKey.PA_ENC_TIMESTAMP_REQUIRED);
    }

    /**
     * Get whether body checksum verified.
     * @return true if body checksum verified
     */
    public boolean isBodyChecksumVerified() {
        return getBoolean(KrbConfigKey.VERIFY_BODY_CHECKSUM);
    }

    /**
     * Get default realm.
     * @return The default realm
     */
    public String getDefaultRealm() {
        return KrbConfHelper.getStringUnderSection(this, KrbConfigKey.DEFAULT_REALM);
    }

    /**
     * Get whether dns look up kdc.
     * @return true if dnc look up kdc
     */
    public boolean getDnsLookUpKdc() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.DNS_LOOKUP_KDC);
    }

    /**
     * Get whether dns look up realm.
     * @return true if dns look up realm
     */
    public boolean getDnsLookUpRealm() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.DNS_LOOKUP_REALM);
    }

    /**
     * Get whether allow weak crypto.
     * @return true if allow weak crypto
     */
    public boolean getAllowWeakCrypto() {
        return KrbConfHelper.getBooleanUnderSection(this, KrbConfigKey.ALLOW_WEAK_CRYPTO);
    }

    /**
     * Get ticket life time.
     * @return The ticket life time
     */
    public long getTicketLifetime() {
        return KrbConfHelper.getLongUnderSection(this, KrbConfigKey.TICKET_LIFETIME);
    }

    /**
     * Get renew life time.
     * @return The renew life time
     */
    public long getRenewLifetime() {
        return KrbConfHelper.getLongUnderSection(this, KrbConfigKey.RENEW_LIFETIME);
    }

    /**
     * Get default tgs encryption types.
     * @return The tgs encryption type list
     */
    public List<EncryptionType> getDefaultTgsEnctypes() {
        return KrbConfHelper.getEncTypesUnderSection(this, KrbConfigKey.DEFAULT_TGS_ENCTYPES);
    }

    /**
     * Get default ticket encryption types.
     * @return The encryption type list
     */
    public List<EncryptionType> getDefaultTktEnctypes() {
        return KrbConfHelper.getEncTypesUnderSection(this, KrbConfigKey.DEFAULT_TKT_ENCTYPES);
    }
}
