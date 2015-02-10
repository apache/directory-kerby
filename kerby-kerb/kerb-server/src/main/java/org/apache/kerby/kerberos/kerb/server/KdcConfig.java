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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;
import org.apache.kerby.kerberos.kerb.common.KrbConfHelper;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;

import java.util.List;

public class KdcConfig {
    protected Conf conf;

    public KdcConfig() {
        this.conf = new Conf();
    }

    public Conf getConf() {
        return this.conf;
    }

    /**
     * Prepare and return backend config
     * @return
     */
    public Config getBackendConfig() {
        return conf.getConfig("IdentityBackend");
    }

    public boolean enableDebug() {
        return conf.getBoolean(KdcConfigKey.KRB_DEBUG);
    }

    public String getKdcServiceName() {
        return conf.getString(KdcConfigKey.KDC_SERVICE_NAME);
    }

    public String getWorkDir() {
        return conf.getString(KdcConfigKey.WORK_DIR);
    }

    public String getKdcHost() {
        return conf.getString(KdcConfigKey.KDC_HOST);
    }

    public int getKdcTcpPort() {
        Integer kdcTcpPort =  KrbConfHelper.getIntUnderSection(conf, KdcConfigKey.KDC_TCP_PORT);
        return kdcTcpPort.intValue();
    }

    public int getKdcUdpPort() {
        Integer kdcUdpPort = KrbConfHelper.getIntUnderSection(conf, KdcConfigKey.KDC_UDP_PORT);
        return kdcUdpPort.intValue();
    }

    public String getKdcRealm() {
        return conf.getString(KdcConfigKey.KDC_REALM);
    }

    public String getKdcDomain() {
        return conf.getString(KdcConfigKey.KDC_DOMAIN);
    }

    public boolean isPreauthRequired() {
        return conf.getBoolean(KdcConfigKey.PREAUTH_REQUIRED);
    }

    public String getTgsPrincipal() {
        return conf.getString(KdcConfigKey.TGS_PRINCIPAL);
    }

    public long getAllowableClockSkew() {
        return conf.getLong(KdcConfigKey.ALLOWABLE_CLOCKSKEW);
    }

    public boolean isEmptyAddressesAllowed() {
        return conf.getBoolean(KdcConfigKey.EMPTY_ADDRESSES_ALLOWED);
    }

    public boolean isForwardableAllowed() {
        return conf.getBoolean(KdcConfigKey.FORWARDABLE_ALLOWED);
    }

    public boolean isPostdatedAllowed() {
        return conf.getBoolean(KdcConfigKey.POSTDATED_ALLOWED);
    }

    public boolean isProxiableAllowed() {
        return conf.getBoolean(KdcConfigKey.PROXIABLE_ALLOWED);
    }

    public boolean isRenewableAllowed() {
        return conf.getBoolean(KdcConfigKey.RENEWABLE_ALLOWED);
    }

    public long getMaximumRenewableLifetime() {
        return conf.getLong(KdcConfigKey.MAXIMUM_RENEWABLE_LIFETIME);
    }

    public long getMaximumTicketLifetime() {
        return conf.getLong(KdcConfigKey.MAXIMUM_TICKET_LIFETIME);
    }

    public long getMinimumTicketLifetime() {
        return conf.getLong(KdcConfigKey.MINIMUM_TICKET_LIFETIME);
    }

    public List<EncryptionType> getEncryptionTypes() {
        List<String> eTypes = conf.getList(KdcConfigKey.ENCRYPTION_TYPES);
        return KrbConfHelper.getEncryptionTypes(eTypes);
    }

    public boolean isPaEncTimestampRequired() {
        return conf.getBoolean(KdcConfigKey.PA_ENC_TIMESTAMP_REQUIRED);
    }

    public boolean isBodyChecksumVerified() {
        return conf.getBoolean(KdcConfigKey.VERIFY_BODY_CHECKSUM);
    }

    public String getDefaultLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(conf, KdcConfigKey.DEFAULT);
    }

    public String getKdcLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(conf, KdcConfigKey.KDC);
    }

    public String getAdminLoggingLocation() {
        return KrbConfHelper.getStringUnderSection(conf, KdcConfigKey.ADMIN_SERVER);
    }

    public boolean isRestrictAnonymousToTgt() {
        return KrbConfHelper.getBooleanUnderSection(conf, KdcConfigKey.RESTRICT_ANONYMOUS_TO_TGT);
    }

    public int getKdcMaxDgramReplySize() {
        return KrbConfHelper.getIntUnderSection(conf, KdcConfigKey.KDC_MAX_DGRAM_REPLY_SIZE);
    }
}
