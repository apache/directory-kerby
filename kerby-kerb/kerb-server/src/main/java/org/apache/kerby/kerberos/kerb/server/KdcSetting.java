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
import org.apache.kerby.config.Conf;
import org.apache.kerby.config.Config;

import java.io.File;

/**
 * KDC setting that combines startup options and kdc config.
 */
public class KdcSetting {
    private final KOptions startupOptions;
    private final KdcConfig kdcConfig;
    private Conf backendConfig;

    public KdcSetting(KOptions startupOptions,
                      KdcConfig config, Conf backendConfig) {
        this.startupOptions = startupOptions;
        this.kdcConfig = config;
        this.backendConfig = backendConfig;
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
    public Config getBackendConfig() {
        return backendConfig;
    }

    public File getConfDir() {
        return  startupOptions.getDirOption(KdcServerOption.CONF_DIR);
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
        return tcpPort;
    }

    public boolean allowUdp() {
        Boolean allowUdp = startupOptions.getBooleanOption(KdcServerOption.ALLOW_UDP);
        if (allowUdp == null) {
            allowUdp = kdcConfig.allowKdcUdp();
        }
        return allowUdp;
    }

    public int getKdcUdpPort() {
        int udpPort = startupOptions.getIntegerOption(KdcServerOption.KDC_UDP_PORT);
        if (udpPort < 1) {
            udpPort = kdcConfig.getKdcUdpPort();
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
