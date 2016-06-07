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

import org.apache.kerby.kerberos.kerb.common.Krb5Conf;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Kerb client side configuration API.
 */
public class KrbConfig extends Krb5Conf {
    private static final String LIBDEFAULT = "libdefaults";
    private static final String REALMS = "realms";

    public boolean enableDebug() {
        return getBoolean(KrbConfigKey.KRB_DEBUG, true, LIBDEFAULT);
    }

    /**
     * Get KDC host name
     *
     * @return The kdc host
     */
    public String getKdcHost() {
        return getString(
            KrbConfigKey.KDC_HOST, true, LIBDEFAULT);
    }

    /**
     * Get KDC port, as both TCP and UDP ports
     *
     * @return The kdc host
     */
    public int getKdcPort() {
        Integer kdcPort = getInt(KrbConfigKey.KDC_PORT, true, LIBDEFAULT);
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
        Integer kdcPort = getInt(KrbConfigKey.KDC_TCP_PORT, true, LIBDEFAULT);
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
    public boolean allowUdp() {
        return getBoolean(KrbConfigKey.KDC_ALLOW_UDP, true, LIBDEFAULT)
                || getInt(KrbConfigKey.KDC_UDP_PORT, true, LIBDEFAULT) != null
            || getInt(KrbConfigKey.KDC_PORT, false, LIBDEFAULT) != null;
    }

    /**
     * Is to allow TCP for KDC
     *
     * @return true to allow TCP, false otherwise
     */
    public boolean allowTcp() {
        return getBoolean(KrbConfigKey.KDC_ALLOW_TCP, true, LIBDEFAULT)
                || getInt(KrbConfigKey.KDC_TCP_PORT, true, LIBDEFAULT) != null
            || getInt(KrbConfigKey.KDC_PORT, false, LIBDEFAULT) != null;
    }

    /**
     * Get KDC UDP port
     *
     * @return The kdc udp port
     */
    public int getKdcUdpPort() {
        Integer kdcPort = getInt(KrbConfigKey.KDC_UDP_PORT, true, LIBDEFAULT);
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
        String realm = getString(KrbConfigKey.KDC_REALM, false, LIBDEFAULT);
        if (realm == null) {
            realm = getString(KrbConfigKey.DEFAULT_REALM, false, LIBDEFAULT);
            if (realm == null) {
                realm = (String) KrbConfigKey.KDC_REALM.getDefaultValue();
            }
        }

        return realm;
    }

    /**
     * Get whether preatuh is required.
     * @return true if preauth required
     */
    public boolean isPreauthRequired() {
        return getBoolean(KrbConfigKey.PREAUTH_REQUIRED, true, LIBDEFAULT);
    }

    /**
     * Get tgs principal.
     * @return The tgs principal
     */
    public String getTgsPrincipal() {
        return getString(KrbConfigKey.TGS_PRINCIPAL, true, LIBDEFAULT);
    }

    /**
     * Get allowable clock skew.
     * @return The allowable clock skew
     */
    public long getAllowableClockSkew() {
        return getLong(KrbConfigKey.CLOCKSKEW, true, LIBDEFAULT);
    }

    /**
     * Get whether empty addresses allowed.
     * @return true if empty address is allowed
     */
    public boolean isEmptyAddressesAllowed() {
        return getBoolean(KrbConfigKey.EMPTY_ADDRESSES_ALLOWED, true, LIBDEFAULT);
    }

    /**
     * Get whether forward is allowed.
     * @return true if forward is allowed
     */
    public boolean isForwardableAllowed() {
        return getBoolean(KrbConfigKey.FORWARDABLE, true, LIBDEFAULT);
    }

    /**
     * Get whether post dated is allowed.
     * @return true if post dated is allowed
     */
    public boolean isPostdatedAllowed() {
        return getBoolean(KrbConfigKey.POSTDATED_ALLOWED, true, LIBDEFAULT);
    }

    /**
     * Get whether proxy is allowed.
     * @return true if proxy is allowed
     */
    public boolean isProxiableAllowed() {
        return getBoolean(KrbConfigKey.PROXIABLE, true, LIBDEFAULT);
    }

    /**
     * Get whether renew is allowed.
     * @return true if renew is allowed
     */
    public boolean isRenewableAllowed() {
        return getBoolean(KrbConfigKey.RENEWABLE_ALLOWED, true, LIBDEFAULT);
    }

    /**
     * Get maximum renewable life time.
     * @return The maximum renewable life time
     */
    public long getMaximumRenewableLifetime() {
        return getLong(KrbConfigKey.MAXIMUM_RENEWABLE_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get maximum ticket life time.
     * @return The maximum ticket life time
     */
    public long getMaximumTicketLifetime() {
        return getLong(KrbConfigKey.MAXIMUM_TICKET_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get minimum ticket life time.
     * @return The minimum ticket life time
     */
    public long getMinimumTicketLifetime() {
        return getLong(KrbConfigKey.MINIMUM_TICKET_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get encryption types.
     * @return encryption type list
     */
    public List<EncryptionType> getEncryptionTypes() {
        return getEncTypes(KrbConfigKey.PERMITTED_ENCTYPES, true, LIBDEFAULT);
    }

    /**
     * Get whether pa encrypt timestamp required.
     * @return true if pa encrypt time required
     */
    public boolean isPaEncTimestampRequired() {
        return getBoolean(KrbConfigKey.PA_ENC_TIMESTAMP_REQUIRED, true, LIBDEFAULT);
    }

    /**
     * Get whether body checksum verified.
     * @return true if body checksum verified
     */
    public boolean isBodyChecksumVerified() {
        return getBoolean(KrbConfigKey.VERIFY_BODY_CHECKSUM, true, LIBDEFAULT);
    }

    /**
     * Get default realm.
     * @return The default realm
     */
    public String getDefaultRealm() {
        return getString(KrbConfigKey.DEFAULT_REALM, true, LIBDEFAULT);
    }

    /**
     * Get whether dns look up kdc.
     * @return true if dnc look up kdc
     */
    public boolean getDnsLookUpKdc() {
        return getBoolean(KrbConfigKey.DNS_LOOKUP_KDC, true, LIBDEFAULT);
    }

    /**
     * Get whether dns look up realm.
     * @return true if dns look up realm
     */
    public boolean getDnsLookUpRealm() {
        return getBoolean(KrbConfigKey.DNS_LOOKUP_REALM, true, LIBDEFAULT);
    }

    /**
     * Get whether allow weak crypto.
     * @return true if allow weak crypto
     */
    public boolean getAllowWeakCrypto() {
        return getBoolean(KrbConfigKey.ALLOW_WEAK_CRYPTO, true, LIBDEFAULT);
    }

    /**
     * Get ticket life time.
     * @return The ticket life time
     */
    public long getTicketLifetime() {
        return getLong(KrbConfigKey.TICKET_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get renew life time.
     * @return The renew life time
     */
    public long getRenewLifetime() {
        return getLong(KrbConfigKey.RENEW_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get default tgs encryption types.
     * @return The tgs encryption type list
     */
    public List<EncryptionType> getDefaultTgsEnctypes() {
        return getEncTypes(KrbConfigKey.DEFAULT_TGS_ENCTYPES, true, LIBDEFAULT);
    }

    /**
     * Get default ticket encryption types.
     * @return The encryption type list
     */
    public List<EncryptionType> getDefaultTktEnctypes() {
        return getEncTypes(KrbConfigKey.DEFAULT_TKT_ENCTYPES, true, LIBDEFAULT);
    }

    public List<String> getPkinitAnchors() {
        return Arrays.asList(getStringArray(
                KrbConfigKey.PKINIT_ANCHORS, true, LIBDEFAULT));
    }

    public List<String> getPkinitIdentities() {
        return Arrays.asList(getStringArray(
                KrbConfigKey.PKINIT_IDENTITIES, true, LIBDEFAULT));
    }

    public String getPkinitKdcHostName() {
        return getString(
                KrbConfigKey.PKINIT_KDC_HOSTNAME, true, LIBDEFAULT);
    }

    public List<Object> getRealmSectionItems(String realm, String key) {
        Map<String, Object> map = getRealmSection(realm);
        List<Object> items = null;
        if (map != null) {
            items = new ArrayList<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (entry.getKey().equals(key)) {
                    items.add(entry.getValue());
                }
            }
        }
        return items;
    }

    public Map<String, Object> getRealmSection(String realm) {
        Object realms = getSection(REALMS);
        if (realms != null) {
            Map<String, Object> map = (Map) realms;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (entry.getKey().equals(realm)) {
                    return (Map) entry.getValue();
                }
            }
            return null;
        } else {
            return null;
        }
    }
}
