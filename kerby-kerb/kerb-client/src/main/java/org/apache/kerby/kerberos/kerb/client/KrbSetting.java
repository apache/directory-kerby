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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.KOptions;

/**
 * Krb client setting that combines common options and client config.
 */
public class KrbSetting {
    private final KOptions commonOptions;
    private final KrbConfig krbConfig;

    public KrbSetting(KOptions commonOptions, KrbConfig config) {
        this.commonOptions = commonOptions;
        this.krbConfig = config;
    }

    public String getKdcHost() {
        String kdcHost = commonOptions.getStringOption(KrbOption.KDC_HOST);
        if (kdcHost == null) {
            return krbConfig.getKdcHost();
        }
        return kdcHost;
    }

    public int getKdcTcpPort() {
        int tcpPort = commonOptions.getIntegerOption(KrbOption.KDC_TCP_PORT);
        if (tcpPort > 0) {
            return tcpPort;
        }
        return krbConfig.getKdcTcpPort();
    }

    public boolean allowUdp() {
        Boolean allowUdp = commonOptions.getBooleanOption(KrbOption.ALLOW_UDP);
        if (allowUdp != null) {
            return allowUdp;
        }
        return krbConfig.allowKdcUdp();
    }

    public int getKdcUdpPort() {
        int udpPort = commonOptions.getIntegerOption(KrbOption.KDC_UDP_PORT);
        if (udpPort > 0) {
            return udpPort;
        }
        return krbConfig.getKdcUdpPort();
    }

    public int getTimeout() {
        int timeout = commonOptions.getIntegerOption(KrbOption.CONN_TIMEOUT);
        if (timeout > 0) {
            return timeout;
        }
        return 1000; // by default
    }
}
