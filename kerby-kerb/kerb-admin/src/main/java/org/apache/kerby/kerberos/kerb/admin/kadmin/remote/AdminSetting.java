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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;

/**
 * Admin client setting that combines common options and client config.
 */
public class AdminSetting {
    private final KOptions commonOptions;
    private final AdminConfig adminConfig;

    public AdminSetting(KOptions commonOptions, AdminConfig config) {
        this.commonOptions = commonOptions;
        this.adminConfig = config;
    }

    public AdminSetting(AdminConfig config) {
        this.commonOptions = new KOptions();
        this.adminConfig = config;
    }

    public AdminConfig getAdminConfig() {
        return adminConfig;
    }

    public String getKdcRealm() {
        String kdcRealm = commonOptions.getStringOption(AdminOption.ADMIN_REALM);
        if (kdcRealm == null || kdcRealm.isEmpty()) {
            kdcRealm = adminConfig.getAdminRealm();
        }
        return kdcRealm;
    }

    public String getKdcHost() {
        String kdcHost = commonOptions.getStringOption(AdminOption.ADMIN_HOST);
        if (kdcHost == null) {
            return adminConfig.getAdminHost();
        }
        return kdcHost;
    }

    /**
     * Check kdc tcp setting and see if any bad.
     * @return valid tcp port or -1 if not allowTcp
     * @throws KrbException e
     */
    public int checkGetKdcTcpPort() throws KrbException {
        if (allowTcp()) {
            int kdcPort = getKdcTcpPort();
            if (kdcPort < 1) {
                throw new KrbException("KDC tcp port isn't set or configured");
            }
            return kdcPort;
        }
        return -1;
    }

    /**
     * Check kdc udp setting and see if any bad.
     * @return valid udp port or -1 if not allowUdp
     * @throws KrbException e
     */
    public int checkGetKdcUdpPort() throws KrbException {
        if (allowUdp()) {
            int kdcPort = getKdcUdpPort();
            if (kdcPort < 1) {
                throw new KrbException("KDC udp port isn't set or configured");
            }
            return kdcPort;
        }
        return -1;
    }

    public int getKdcTcpPort() {
        int tcpPort = commonOptions.getIntegerOption(AdminOption.ADMIN_TCP_PORT);
        if (tcpPort > 0) {
            return tcpPort;
        }
        return adminConfig.getAdminTcpPort();
    }

    public boolean allowUdp() {
        Boolean allowUdp = commonOptions.getBooleanOption(
                AdminOption.ALLOW_UDP, adminConfig.allowUdp());
        return allowUdp;
    }

    public boolean allowTcp() {
        Boolean allowTcp = commonOptions.getBooleanOption(
                AdminOption.ALLOW_TCP, adminConfig.allowTcp());
        return allowTcp;
    }

    public int getKdcUdpPort() {
        int udpPort = commonOptions.getIntegerOption(AdminOption.ADMIN_UDP_PORT);
        if (udpPort > 0) {
            return udpPort;
        }
        return adminConfig.getAdminUdpPort();
    }

    public int getTimeout() {
        int timeout = commonOptions.getIntegerOption(AdminOption.CONN_TIMEOUT);
        if (timeout > 0) {
            return timeout;
        }
        return 1000; // by default
    }
}
