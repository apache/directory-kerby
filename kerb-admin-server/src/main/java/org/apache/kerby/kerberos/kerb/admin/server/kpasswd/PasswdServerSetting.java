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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;

/**
 * Passwd Server setting that combines startup options and passwd config.
 */
public class PasswdServerSetting {
    private final KOptions startupOptions;
    private final PasswdServerConfig passwdServerConfig;
    private final BackendConfig backendConfig;

    /**
     * PasswdServerSetting constructor
     * @param startupOptions startup options
     * @param config passwd configuration
     * @param backendConfig backend configuration
     */
    public PasswdServerSetting(KOptions startupOptions,
                              PasswdServerConfig config,
                              BackendConfig backendConfig) {
        this.startupOptions = startupOptions;
        this.passwdServerConfig = config;
        this.backendConfig = backendConfig;
    }

    public PasswdServerSetting(PasswdServerConfig passwdServerConfig,
                              BackendConfig backendConfig) {
        this(new KOptions(), passwdServerConfig, backendConfig);
    }

    /**
     * Get the Passwd Server config.
     * @return passwd configuration
     */
    public PasswdServerConfig getPasswdServerConfig() {
        return passwdServerConfig;
    }

    /**
     * Get the backend config.
     * @return backend configuration
     */
    public BackendConfig getBackendConfig() {
        return backendConfig;
    }

    public String getPasswdHost() {
        String passwdHost = startupOptions.getStringOption(
                PasswdServerOption.ADMIN_HOST);
        if (passwdHost == null) {
            passwdHost = passwdServerConfig.getPasswdHost();
        }
        return passwdHost;
    }

    /**
     * Check passwd tcp setting and see if any bad.
     * @return valid tcp port or -1 if not allowTcp
     * @throws KrbException e
     */
    public int checkGetPasswdTcpPort() throws KrbException {
        if (allowTcp()) {
            int passwdPort = getPasswdTcpPort();
            if (passwdPort < 1) {
                throw new KrbException("Passwd Server tcp port isn't set or configured");
            }
            return passwdPort;
        }
        return -1;
    }

    /**
     * Check passwd udp setting and see if any bad.
     * @return valid udp port or -1 if not allowUdp
     * @throws KrbException e
     */
    public int checkGetPasswdUdpPort() throws KrbException {
        if (allowUdp()) {
            int passwdPort = getPasswdUdpPort();
            if (passwdPort < 1) {
                throw new KrbException("Passwd Server udp port isn't set or configured");
            }
            return passwdPort;
        }
        return -1;
    }

    /**
     * Get passwd tcp port
     *
     * @return passwd tcp port
     */
    public int getPasswdTcpPort() {
        int tcpPort = startupOptions.getIntegerOption(PasswdServerOption.ADMIN_TCP_PORT);
        if (tcpPort < 1) {
            tcpPort = passwdServerConfig.getPasswdTcpPort();
        }
        if (tcpPort < 1) {
            tcpPort = getPasswdPort();
        }

        return tcpPort;
    }

    /**
     * Get passwd port
     *
     * @return passwd port
     */
    public int getPasswdPort() {
        int passwdPort = startupOptions.getIntegerOption(PasswdServerOption.ADMIN_PORT);
        if (passwdPort < 1) {
            passwdPort = passwdServerConfig.getPasswdPort();
        }
        return passwdPort;
    }

    /**
     * Get whether tcp protocol is allowed
     * @return tcp protocol is allowed or not
     */
    public boolean allowTcp() {
        Boolean allowTcp = startupOptions.getBooleanOption(
                PasswdServerOption.ALLOW_TCP, passwdServerConfig.allowTcp());
        return allowTcp;
    }

    /**
     * Get whether udp protocol is allowed
     * @return udp protocol is allowed or not
     */
    public boolean allowUdp() {
        Boolean allowUdp = startupOptions.getBooleanOption(
                PasswdServerOption.ALLOW_UDP, passwdServerConfig.allowUdp());
        return allowUdp;
    }

    /**
     * Get passwd udp port
     *
     * @return udp port
     */
    public int getPasswdUdpPort() {
        int udpPort = startupOptions.getIntegerOption(PasswdServerOption.ADMIN_UDP_PORT);
        if (udpPort < 1) {
            udpPort = passwdServerConfig.getPasswdUdpPort();
        }
        if (udpPort < 1) {
            udpPort = getPasswdPort();
        }

        return udpPort;
    }

    /**
     * Get Passwd Server realm.
     * @return Passwd Server realm
     */
    public String getPasswdRealm() {
        String passwdRealm = startupOptions.getStringOption(PasswdServerOption.ADMIN_REALM);
        if (passwdRealm == null || passwdRealm.isEmpty()) {
            passwdRealm = passwdServerConfig.getPasswdRealm();
        }
        return passwdRealm;
    }
}
