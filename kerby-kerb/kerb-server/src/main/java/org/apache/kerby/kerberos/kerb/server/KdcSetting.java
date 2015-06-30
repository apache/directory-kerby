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

import org.apache.kerby.KOptions;

/**
 * KDC setting that combines startup options and kdc config.
 */
public class KdcSetting {
    private final KOptions startupOptions;
    private final KdcConfig kdcConfig;
    private final BackendConfig backendConfig;

    public KdcSetting(KOptions startupOptions,
                      KdcConfig config, BackendConfig backendConfig) {
        this.startupOptions = startupOptions;
        this.kdcConfig = config;
        this.backendConfig = backendConfig;
    }

    public KdcSetting(KdcConfig kdcConfig, BackendConfig backendConfig) {
        this(new KOptions(), kdcConfig, backendConfig);
    }

    /**
     * Get the KDC config.
     * @return
     */
    public KdcConfig getKdcConfig() {
        return kdcConfig;
    }

    /**
     * Get the backend config.
     * @return
     */
    public BackendConfig getBackendConfig() {
        return backendConfig;
    }

    public String getKdcHost() {
        String kdcHost = startupOptions.getStringOption(
                KdcServerOption.KDC_HOST);
        if (kdcHost == null) {
            kdcHost = kdcConfig.getKdcHost();
        }
        return kdcHost;
    }

    public int getKdcTcpPort() {
        int tcpPort = startupOptions.getIntegerOption(KdcServerOption.KDC_TCP_PORT);
        if (tcpPort < 1) {
            tcpPort = kdcConfig.getKdcTcpPort();
        }
        if (tcpPort < 1) {
            tcpPort = getKdcPort();
        }

        return tcpPort;
    }

    public int getKdcPort() {
        int kdcPort = startupOptions.getIntegerOption(KdcServerOption.KDC_PORT);
        if (kdcPort < 1) {
            kdcPort = kdcConfig.getKdcPort();
        }
        return kdcPort;
    }

    public boolean allowTcp() {
        Boolean allowTcp = startupOptions.getBooleanOption(KdcServerOption.ALLOW_TCP);
        if (allowTcp == null) {
            allowTcp = kdcConfig.allowTcp();
        }

        return allowTcp != null ? allowTcp : false;
    }

    public boolean allowUdp() {
        Boolean allowUdp = startupOptions.getBooleanOption(KdcServerOption.ALLOW_UDP);
        if (allowUdp == null) {
            allowUdp = kdcConfig.allowUdp();
        }
        return allowUdp != null ? allowUdp : false;
    }

    public int getKdcUdpPort() {
        int udpPort = startupOptions.getIntegerOption(KdcServerOption.KDC_UDP_PORT);
        if (udpPort < 1) {
            udpPort = kdcConfig.getKdcUdpPort();
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
        String kdcRealm = startupOptions.getStringOption(KdcServerOption.KDC_REALM);
        if (kdcRealm == null || kdcRealm.isEmpty()) {
            kdcRealm = kdcConfig.getKdcRealm();
        }
        return kdcRealm;
    }
}
