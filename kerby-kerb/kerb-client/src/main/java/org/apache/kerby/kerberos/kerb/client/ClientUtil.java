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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class ClientUtil {
    private ClientUtil() { }

    private static final Logger LOG = LoggerFactory.getLogger(ClientUtil.class);
    private static final String KRB5_FILE_NAME = "krb5.conf";
    private static final String KRB5_ENV_NAME = "KRB5_CONFIG";

    /**
     * Load krb5.conf from specified conf dir.
     * @param confDir The conf dir
     * @return KrbConfig
     * @throws KrbException e
     */
    public static KrbConfig getConfig(File confDir) throws KrbException {
        File confFile = new File(confDir, KRB5_FILE_NAME);
        if (!confFile.exists()) {
            throw new KrbException(KRB5_FILE_NAME + " not found");
        }

        if (confFile != null && confFile.exists()) {
            KrbConfig krbConfig = new KrbConfig();
            try {
                krbConfig.addKrb5Config(confFile);
                return krbConfig;
            } catch (IOException e) {
                throw new KrbException("Failed to load krb config "
                        + confFile.getAbsolutePath());
            }
        }

        return null;
    }

    /**
     * Load default krb5.conf
     * @return The KrbConfig
     * @throws KrbException e
     */
    public static KrbConfig getDefaultConfig() throws KrbException {
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

        KrbConfig krbConfig = new KrbConfig();
        if (confFile != null && confFile.exists()) {
            try {
                krbConfig.addKrb5Config(confFile);
            } catch (IOException e) {
                throw new KrbException("Failed to load krb config "
                        + confFile.getAbsolutePath());
            }
        }

        return krbConfig;
    }

    /**
     * Get KDC network transport addresses according to krb client setting.
     * @param setting The krb setting
     * @param kdcString The kdc string, may include the port number
     * @return UDP and TCP addresses pair
     * @throws KrbException e
     */
    public static TransportPair getTransportPair(
            KrbSetting setting, String kdcString) throws KrbException, IOException {
        TransportPair result = new TransportPair();
        int tcpPort = setting.checkGetKdcTcpPort();
        int udpPort = setting.checkGetKdcUdpPort();

        int port = 0;
        String kdc;
        String portStr = null;

        // Explicit IPv6 in []
        if (kdcString.charAt(0) == '[') {
            int pos = kdcString.indexOf(']', 1);
            if (pos == -1) {
                throw new IOException("Illegal KDC: " + kdcString);
            }
            kdc = kdcString.substring(1, pos);
            // with port number
            if (pos != kdcString.length() - 1) {
                if (kdcString.charAt(pos + 1) != ':') {
                    throw new IOException("Illegal KDC: " + kdcString);
                }
                portStr = kdcString.substring(pos + 2);
            }
        } else {
            int colon = kdcString.indexOf(':');
            // Hostname or IPv4 host only
            if (colon == -1) {
                kdc = kdcString;
            } else {
                int nextColon = kdcString.indexOf(':', colon + 1);
                // >=2 ":", IPv6 with no port
                if (nextColon > 0) {
                    kdc = kdcString;
                } else {
                    // 1 ":", hostname or IPv4 with port
                    kdc = kdcString.substring(0, colon);
                    portStr = kdcString.substring(colon + 1);
                }
            }
        }
        if (portStr != null) {
            int tempPort = parsePositiveIntString(portStr);
            if (tempPort > 0) {
                port = tempPort;
            }
        }
        if (port != 0) {
            tcpPort = port;
            udpPort = port;
        }
        if (tcpPort > 0) {
            result.tcpAddress = new InetSocketAddress(
                    kdc, tcpPort);
        }
        if (udpPort > 0) {
            result.udpAddress = new InetSocketAddress(
                    kdc, udpPort);
        }
        return result;
    }

    private static int parsePositiveIntString(String intString) {
        if (intString == null) {
            return -1;
        }
        int ret = -1;
        try {
            ret = Integer.parseInt(intString);
        } catch (Exception exc) {
            return -1;
        }
        if (ret >= 0) {
            return ret;
        }
        return -1;
    }

    /**
     * Returns a list of KDC
     *
     * @throws KrbException if there's no way to find KDC for the realm
     * @return the list of KDC, always non null
     */
    public static List<String> getKDCList(KrbSetting krbSetting) throws KrbException {

        List<String> kdcList = new ArrayList<>();
        kdcList.add(krbSetting.getKdcHost());
        /*get the kdc realm */
        String realm = krbSetting.getKdcRealm();
        if (realm != null) {
            KrbConfig krbConfig = krbSetting.getKrbConfig();
            List<Object> kdcs = krbConfig.getRealmSectionItems(realm, "kdc");
            if (kdcs != null) {
                for (Object object : kdcs) {
                    kdcList.add(object != null ? object.toString() : null);
                }
            }

            if (kdcList == null) {
                LOG.info("Cannot get kdc for realm " + realm);
            }
        } else {
            throw new KrbException("Can't get the realm");
        }
        return kdcList;
    }
}
