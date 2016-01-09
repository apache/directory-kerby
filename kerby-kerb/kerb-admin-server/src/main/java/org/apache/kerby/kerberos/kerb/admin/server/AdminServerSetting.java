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

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;

/**
 * KDC setting that combines startup options and kdc config.
 */
public class AdminServerSetting {
    private final KOptions startupOptions;
    private final AdminServerConfig adminServerConfig;
    private final BackendConfig backendConfig;

    /**
     * AdminServerSetting constructor
     * @param startupOptions startup options
     * @param config kdc configuration
     * @param backendConfig backend configuration
     */
    public AdminServerSetting(KOptions startupOptions,
                              AdminServerConfig config, BackendConfig backendConfig) {
        this.startupOptions = startupOptions;
        this.adminServerConfig = config;
        this.backendConfig = backendConfig;
    }

    public AdminServerSetting(AdminServerConfig adminServerConfig, BackendConfig backendConfig) {
        this(new KOptions(), adminServerConfig, backendConfig);
    }

    /**
     * Get the KDC config.
     * @return kdc configuration
     */
    public AdminServerConfig getAdminServerConfig() {
        return adminServerConfig;
    }

    /**
     * Get the backend config.
     * @return backend configuration
     */
    public BackendConfig getBackendConfig() {
        return backendConfig;
    }

    public String getKdcHost() {
        String kdcHost = startupOptions.getStringOption(
                AdminServerOption.KDC_HOST);
        if (kdcHost == null) {
            kdcHost = adminServerConfig.getKdcHost();
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

    /**
     * Get kdc tcp port
     *
     * @return kdc tcp port
     */
    public int getKdcTcpPort() {
        int tcpPort = startupOptions.getIntegerOption(AdminServerOption.KDC_TCP_PORT);
        if (tcpPort < 1) {
            tcpPort = adminServerConfig.getKdcTcpPort();
        }
        if (tcpPort < 1) {
            tcpPort = getKdcPort();
        }

        return tcpPort;
    }

    /**
     * Get kdc port
     *
     * @return kdc port
     */
    public int getKdcPort() {
        int kdcPort = startupOptions.getIntegerOption(AdminServerOption.KDC_PORT);
        if (kdcPort < 1) {
            kdcPort = adminServerConfig.getKdcPort();
        }
        return kdcPort;
    }

    /**
     * Get whether tcp protocol is allowed
     * @return tcp protocol is allowed or not
     */
    public boolean allowTcp() {
        Boolean allowTcp = startupOptions.getBooleanOption(
                AdminServerOption.ALLOW_TCP, adminServerConfig.allowTcp());
        return allowTcp;
    }

    /**
     * Get whether udp protocol is allowed
     * @return udp protocol is allowed or not
     */
    public boolean allowUdp() {
        Boolean allowUdp = startupOptions.getBooleanOption(
                AdminServerOption.ALLOW_UDP, adminServerConfig.allowUdp());
        return allowUdp;
    }

    /**
     * Get kdc udp port
     *
     * @return udp port
     */
    public int getKdcUdpPort() {
        int udpPort = startupOptions.getIntegerOption(AdminServerOption.KDC_UDP_PORT);
        if (udpPort < 1) {
            udpPort = adminServerConfig.getKdcUdpPort();
        }
        if (udpPort < 1) {
            udpPort = getKdcPort();
        }

        return udpPort;
    }

    /**
     * Get KDC realm.
     * @return KDC realm
     */
    public String getKdcRealm() {
        String kdcRealm = startupOptions.getStringOption(AdminServerOption.KDC_REALM);
        if (kdcRealm == null || kdcRealm.isEmpty()) {
            kdcRealm = adminServerConfig.getKdcRealm();
        }
        return kdcRealm;
    }
}
