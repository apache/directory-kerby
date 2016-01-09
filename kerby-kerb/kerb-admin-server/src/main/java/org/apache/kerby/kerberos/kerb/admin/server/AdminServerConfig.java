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
package org.apache.kerby.kerberos.kerb.admin.server;

import org.apache.kerby.kerberos.kerb.common.Krb5Conf;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

import java.util.Arrays;
import java.util.List;

/**
 * Kerb KDC side configuration API.
 */
public class AdminServerConfig extends Krb5Conf {
    private static final String KDCDEFAULT = "kdcdefaults";

    public boolean enableDebug() {
        return getBoolean(AdminServerConfigKey.KRB_DEBUG, true, KDCDEFAULT);
    }

    public String getKdcServiceName() {
        return getString(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_SERVICE_NAME, true, KDCDEFAULT);
    }

    public String getKdcHost() {
        return getString(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_HOST, true, KDCDEFAULT);
    }

    public int getKdcPort() {
        Integer kdcPort = getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_PORT, true, KDCDEFAULT);
        if (kdcPort != null && kdcPort > 0) {
            return kdcPort.intValue();
        }
        return -1;
    }

    public int getKdcTcpPort() {
        Integer kdcTcpPort = getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_TCP_PORT, true, KDCDEFAULT);
        if (kdcTcpPort != null && kdcTcpPort > 0) {
            return kdcTcpPort.intValue();
        }
        return getKdcPort();
    }

    /**
     * Is to allow TCP for KDC
     * @return true to allow TCP, false otherwise
     */
    public Boolean allowTcp() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_ALLOW_TCP, true, KDCDEFAULT)
                || getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_TCP_PORT, true, KDCDEFAULT) != null
            || getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_PORT, false, KDCDEFAULT) != null;
    }

    /**
     * Is to allow UDP for KDC
     * @return true to allow UDP, false otherwise
     */
    public Boolean allowUdp() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_ALLOW_UDP, true, KDCDEFAULT)
                || getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_UDP_PORT, true, KDCDEFAULT) != null
            || getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_PORT, false, KDCDEFAULT) != null;
    }

    public int getKdcUdpPort() {
        Integer kdcUdpPort = getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_UDP_PORT, true, KDCDEFAULT);
        if (kdcUdpPort != null && kdcUdpPort > 0) {
            return kdcUdpPort.intValue();
        }
        return getKdcPort();
    }

    public String getKdcRealm() {
        return getString(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_REALM, true, KDCDEFAULT);
    }

    public String getKdcDomain() {
        return getString(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_DOMAIN, true, KDCDEFAULT);
    }

    public boolean isPreauthRequired() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.PREAUTH_REQUIRED, true, KDCDEFAULT);
    }

    public boolean isAllowTokenPreauth() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.ALLOW_TOKEN_PREAUTH, true, KDCDEFAULT);
    }

    public long getAllowableClockSkew() {
        return getLong(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.ALLOWABLE_CLOCKSKEW, true, KDCDEFAULT);
    }

    public boolean isEmptyAddressesAllowed() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.EMPTY_ADDRESSES_ALLOWED, true, KDCDEFAULT);
    }

    public boolean isForwardableAllowed() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.FORWARDABLE_ALLOWED, true, KDCDEFAULT);
    }

    public boolean isPostdatedAllowed() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.POSTDATED_ALLOWED, true, KDCDEFAULT);
    }

    public boolean isProxiableAllowed() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.PROXIABLE_ALLOWED, true, KDCDEFAULT);
    }

    public boolean isRenewableAllowed() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.RENEWABLE_ALLOWED, true, KDCDEFAULT);
    }

    public long getMaximumRenewableLifetime() {
        return getLong(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.MAXIMUM_RENEWABLE_LIFETIME, true, KDCDEFAULT);
    }

    public long getMaximumTicketLifetime() {
        return getLong(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.MAXIMUM_TICKET_LIFETIME, true, KDCDEFAULT);
    }

    public long getMinimumTicketLifetime() {
        return getLong(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.MINIMUM_TICKET_LIFETIME, true, KDCDEFAULT);
    }

    public List<EncryptionType> getEncryptionTypes() {
        return getEncTypes(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.ENCRYPTION_TYPES, true, KDCDEFAULT);
    }

    public boolean isPaEncTimestampRequired() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.PA_ENC_TIMESTAMP_REQUIRED, true, KDCDEFAULT);
    }

    public boolean isBodyChecksumVerified() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.VERIFY_BODY_CHECKSUM, true, KDCDEFAULT);
    }

    public boolean isRestrictAnonymousToTgt() {
        return getBoolean(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.RESTRICT_ANONYMOUS_TO_TGT, true, KDCDEFAULT);
    }

    public int getKdcMaxDgramReplySize() {
        return getInt(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.KDC_MAX_DGRAM_REPLY_SIZE, true, KDCDEFAULT);
    }

    public String getVerifyKeyConfig() {
        return getString(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.TOKEN_VERIFY_KEYS, true, KDCDEFAULT);
    }

    public String getDecryptionKeyConfig() {
        return getString(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.TOKEN_DECRYPTION_KEYS, true, KDCDEFAULT);
    }

    public List<String> getIssuers() {
        return Arrays.asList(getStringArray(org.apache.kerby.kerberos.kerb.server.KdcConfigKey.TOKEN_ISSUERS, true, KDCDEFAULT));
    }

    public List<String> getPkinitAnchors() {
        return Arrays.asList(getString(
                org.apache.kerby.kerberos.kerb.server.KdcConfigKey.PKINIT_ANCHORS, true, KDCDEFAULT));
    }

    public String getPkinitIdentity() {
        return getString(
                KdcConfigKey.PKINIT_IDENTITY, true, KDCDEFAULT);
    }
}
