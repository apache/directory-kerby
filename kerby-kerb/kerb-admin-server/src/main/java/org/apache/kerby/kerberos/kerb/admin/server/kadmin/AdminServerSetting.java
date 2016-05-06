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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.ServerSetting;

/**
 * Admin Server setting that combines startup options and admin config.
 */
public class AdminServerSetting implements ServerSetting {
    private final KOptions startupOptions;
    private final AdminServerConfig adminServerConfig;
    private final KdcConfig kdcConfig;
    private final BackendConfig backendConfig;

    /**
     * AdminServerSetting constructor
     * @param startupOptions startup options
     * @param adminServerConfig admin configuration
     * @param kdcConfig kdc configuration
     * @param backendConfig backend configuration
     */
    public AdminServerSetting(KOptions startupOptions,
                              AdminServerConfig adminServerConfig,
                              KdcConfig kdcConfig,
                              BackendConfig backendConfig) {
        this.startupOptions = startupOptions;
        this.adminServerConfig = adminServerConfig;
        this.kdcConfig = kdcConfig;
        this.backendConfig = backendConfig;
    }

    public AdminServerSetting(AdminServerConfig adminServerConfig, 
                              BackendConfig backendConfig, KdcConfig kdcConfig) {
        this(new KOptions(), adminServerConfig, kdcConfig, backendConfig);
    }

    /**
     * Get the Admin Server config.
     * @return admin configuration
     */
    public AdminServerConfig getAdminServerConfig() {
        return adminServerConfig;
    }

    /**
     * Get the realm of KDC of Admin Server.
     * @return the realm of KDC
     */
    @Override
    public String getKdcRealm() {
         return kdcConfig.getKdcRealm();
    }

    /**
     * Get the KDC config of Admin server.
     * @return the KDC configuration
     */
    @Override
    public KdcConfig getKdcConfig() {
        return kdcConfig;
    }

    /**
     * Get the backend config.
     * @return backend configuration
     */
    public BackendConfig getBackendConfig() {
        return backendConfig;
    }

    public String getAdminHost() {
        String adminHost = startupOptions.getStringOption(
                AdminServerOption.ADMIN_HOST);
        if (adminHost == null) {
            adminHost = adminServerConfig.getAdminHost();
        }
        return adminHost;
    }

    /**
     * Check admin tcp setting and see if any bad.
     * @return valid tcp port or -1 if not allowTcp
     * @throws KrbException e
     */
    public int checkGetAdminTcpPort() throws KrbException {
        if (allowTcp()) {
            int adminPort = getAdminTcpPort();
            if (adminPort < 1) {
                throw new KrbException("Admin Server tcp port isn't set or configured");
            }
            return adminPort;
        }
        return -1;
    }

    /**
     * Check admin udp setting and see if any bad.
     * @return valid udp port or -1 if not allowUdp
     * @throws KrbException e
     */
    public int checkGetAdminUdpPort() throws KrbException {
        if (allowUdp()) {
            int adminPort = getAdminUdpPort();
            if (adminPort < 1) {
                throw new KrbException("Admin Server udp port isn't set or configured");
            }
            return adminPort;
        }
        return -1;
    }

    /**
     * Get admin tcp port
     *
     * @return admin tcp port
     */
    public int getAdminTcpPort() {
        int tcpPort = startupOptions.getIntegerOption(AdminServerOption.ADMIN_TCP_PORT);
        if (tcpPort < 1) {
            tcpPort = adminServerConfig.getAdminTcpPort();
        }
        if (tcpPort < 1) {
            tcpPort = getAdminPort();
        }

        return tcpPort;
    }

    /**
     * Get admin port
     *
     * @return admin port
     */
    public int getAdminPort() {
        int adminPort = startupOptions.getIntegerOption(AdminServerOption.ADMIN_PORT);
        if (adminPort < 1) {
            adminPort = adminServerConfig.getAdminPort();
        }
        return adminPort;
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
     * Get admin udp port
     *
     * @return udp port
     */
    public int getAdminUdpPort() {
        int udpPort = startupOptions.getIntegerOption(AdminServerOption.ADMIN_UDP_PORT);
        if (udpPort < 1) {
            udpPort = adminServerConfig.getAdminUdpPort();
        }
        if (udpPort < 1) {
            udpPort = getAdminPort();
        }

        return udpPort;
    }

    /**
     * Get Admin Server realm.
     * @return Admin Server realm
     */
    public String getAdminRealm() {
        String adminRealm = startupOptions.getStringOption(AdminServerOption.ADMIN_REALM);
        if (adminRealm == null || adminRealm.isEmpty()) {
            adminRealm = adminServerConfig.getAdminRealm();
        }
        return adminRealm;
    }
}
