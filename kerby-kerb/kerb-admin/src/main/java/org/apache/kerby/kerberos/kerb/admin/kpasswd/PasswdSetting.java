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
package org.apache.kerby.kerberos.kerb.admin.kpasswd;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;

/**
 * Admin client setting that combines common options and client config.
 */
public class PasswdSetting {
    private final KOptions commonOptions;
    private final PasswdConfig passwdConfig;

    public PasswdSetting(KOptions commonOptions, PasswdConfig config) {
        this.commonOptions = commonOptions;
        this.passwdConfig = config;
    }

    public PasswdSetting(PasswdConfig config) {
        this.commonOptions = new KOptions();
        this.passwdConfig = config;
    }

    public PasswdConfig getPasswdConfig() {
        return passwdConfig;
    }

    public String getKdcRealm() {
        String kdcRealm = commonOptions.getStringOption(PasswdOption.ADMIN_REALM);
        if (kdcRealm == null || kdcRealm.isEmpty()) {
            kdcRealm = passwdConfig.getAdminRealm();
        }
        return kdcRealm;
    }

    public String getKdcHost() {
        String kdcHost = commonOptions.getStringOption(PasswdOption.ADMIN_HOST);
        if (kdcHost == null) {
            return passwdConfig.getAdminHost();
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
        int tcpPort = commonOptions.getIntegerOption(PasswdOption.ADMIN_TCP_PORT);
        if (tcpPort > 0) {
            return tcpPort;
        }
        return passwdConfig.getAdminTcpPort();
    }

    public boolean allowUdp() {
        Boolean allowUdp = commonOptions.getBooleanOption(
                PasswdOption.ALLOW_UDP, passwdConfig.allowUdp());
        return allowUdp;
    }

    public boolean allowTcp() {
        Boolean allowTcp = commonOptions.getBooleanOption(
                PasswdOption.ALLOW_TCP, passwdConfig.allowTcp());
        return allowTcp;
    }

    public int getKdcUdpPort() {
        int udpPort = commonOptions.getIntegerOption(PasswdOption.ADMIN_UDP_PORT);
        if (udpPort > 0) {
            return udpPort;
        }
        return passwdConfig.getAdminUdpPort();
    }

    public int getTimeout() {
        int timeout = commonOptions.getIntegerOption(PasswdOption.CONN_TIMEOUT);
        if (timeout > 0) {
            return timeout;
        }
        return 1000; // by default
    }
}
