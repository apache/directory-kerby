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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;

public final class PasswdUtil {
    private PasswdUtil() { }

    private static final String KRB5_FILE_NAME = "kpasswdClient.conf";
    private static final String KRB5_ENV_NAME = "KRB5_CONFIG";

    /**
     * Load krb5.conf from specified conf dir.
     * @param confDir The conf dir
     * @return PasswdConfig
     * @throws KrbException e
     */
    public static PasswdConfig getConfig(File confDir) throws KrbException {
        File confFile = new File(confDir, KRB5_FILE_NAME);
        if (!confFile.exists()) {
            throw new KrbException(KRB5_FILE_NAME + " not found");
        }

        if (confFile != null && confFile.exists()) {
            PasswdConfig adminConfig = new PasswdConfig();
            try {
                adminConfig.addKrb5Config(confFile);
                return adminConfig;
            } catch (IOException e) {
                throw new KrbException("Failed to load krb config "
                        + confFile.getAbsolutePath());
            }
        }

        return null;
    }

    /**
     * Load default krb5.conf
     * @return The PasswdConfig
     * @throws KrbException e
     */
    public static PasswdConfig getDefaultConfig() throws KrbException {
        File confFile = null;
        File confDir;
        String tmpEnv;

        try {
            Map<String, String> mapEnv = System.getenv();
            tmpEnv = mapEnv.get(KRB5_ENV_NAME);
        } catch (SecurityException e) {
            tmpEnv = null;
        }
        if (tmpEnv != null) {
            confFile = new File(tmpEnv);
            if (!confFile.exists()) {
                throw new KrbException("krb5 conf not found. Invalid env "
                        + KRB5_ENV_NAME);
            }
        } else {
            confDir = new File("/etc/"); // for Linux. TODO: fix for Win etc.
            if (confDir.exists()) {
                confFile = new File(confDir, "krb5.conf");
            }
        }

        PasswdConfig adminConfig = new PasswdConfig();
        if (confFile != null && confFile.exists()) {
            try {
                adminConfig.addKrb5Config(confFile);
            } catch (IOException e) {
                throw new KrbException("Failed to load krb config "
                        + confFile.getAbsolutePath());
            }
        }

        return adminConfig;
    }

    /**
     * Get KDC network transport addresses according to krb client setting.
     * @param setting The krb setting
     * @return UDP and TCP addresses pair
     * @throws KrbException e
     */
    public static TransportPair getTransportPair(
            PasswdSetting setting) throws KrbException {
        TransportPair result = new TransportPair();

        int tcpPort = setting.checkGetKdcTcpPort();
        if (tcpPort > 0) {
            result.tcpAddress = new InetSocketAddress(
                    setting.getKdcHost(), tcpPort);
        }
        int udpPort = setting.checkGetKdcUdpPort();
        if (udpPort > 0) {
            result.udpAddress = new InetSocketAddress(
                    setting.getKdcHost(), udpPort);
        }

        return result;
    }
}
