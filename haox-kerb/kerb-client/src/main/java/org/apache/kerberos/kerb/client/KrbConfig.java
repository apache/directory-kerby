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
package org.apache.kerberos.kerb.client;

import org.apache.haox.config.Conf;
import org.apache.kerberos.kerb.common.KrbConfHelper;
import org.apache.kerberos.kerb.spec.common.EncryptionType;

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
        return conf.getLong(KrbConfigKey.ALLOWABLE_CLOCKSKEW);
    }

    public boolean isEmptyAddressesAllowed() {
        return conf.getBoolean(KrbConfigKey.EMPTY_ADDRESSES_ALLOWED);
    }

    public boolean isForwardableAllowed() {
        return conf.getBoolean(KrbConfigKey.FORWARDABLE_ALLOWED);
    }

    public boolean isPostdatedAllowed() {
        return conf.getBoolean(KrbConfigKey.POSTDATED_ALLOWED);
    }

    public boolean isProxiableAllowed() {
        return conf.getBoolean(KrbConfigKey.PROXIABLE_ALLOWED);
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
        return KrbConfHelper.getEncryptionTypes(
                conf.getList(KrbConfigKey.ENCRYPTION_TYPES));
    }

    public boolean isPaEncTimestampRequired() {
        return conf.getBoolean(KrbConfigKey.PA_ENC_TIMESTAMP_REQUIRED);
    }

    public boolean isBodyChecksumVerified() {
        return conf.getBoolean(KrbConfigKey.VERIFY_BODY_CHECKSUM);
    }
}
