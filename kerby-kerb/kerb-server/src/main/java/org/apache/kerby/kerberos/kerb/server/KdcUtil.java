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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.backend.MemoryIdentityBackend;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * KDC side utilities.
 */
public final class KdcUtil {

    private KdcUtil() { }

    /**
     * Get kdc configuration
     * @param confDir configuration directory
     * @return kdc configuration
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public static KdcConfig getKdcConfig(File confDir) throws KrbException {
        File kdcConfFile = new File(confDir, "kdc.conf");
        if (kdcConfFile.exists()) {
            KdcConfig kdcConfig = new KdcConfig();
            try {
                kdcConfig.addIniConfig(kdcConfFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the kdc configuration file "
                        + kdcConfFile.getAbsolutePath());
            }
            return kdcConfig;
        }

        return null;
    }

    /**
     * Get backend configuration
     * @param confDir configuration directory
     * @return backend configuration
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public static BackendConfig getBackendConfig(File confDir) throws KrbException {
        File backendConfigFile = new File(confDir, "backend.conf");
        if (backendConfigFile.exists()) {
            BackendConfig backendConfig = new BackendConfig();
            try {
                backendConfig.addIniConfig(backendConfigFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the backend configuration file "
                        + backendConfigFile.getAbsolutePath());
            }
            return backendConfig;
        }

        return null;
    }

    /**
     * Init the identity backend from backend configuration.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     * @param backendConfig backend configuration information
     * @return backend
     */
    public static IdentityBackend getBackend(
            BackendConfig backendConfig) throws KrbException {
        String backendClassName = backendConfig.getString(
                KdcConfigKey.KDC_IDENTITY_BACKEND);
        if (backendClassName == null) {
            backendClassName = MemoryIdentityBackend.class.getCanonicalName();
        }

        Class<?> backendClass;
        try {
            backendClass = Class.forName(backendClassName);
        } catch (ClassNotFoundException e) {
            throw new KrbException("Failed to load backend class: "
                    + backendClassName);
        }

        IdentityBackend backend;
        try {
            backend = (IdentityBackend) backendClass.newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new KrbException("Failed to create backend: "
                    + backendClassName);
        }

        backend.setConfig(backendConfig);
        backend.initialize();
        return backend;
    }

    /**
     * Get KDC network transport addresses according to KDC setting.
     * @param setting kdc setting
     * @return UDP and TCP addresses pair
     * @throws KrbException e
     */
    public static TransportPair getTransportPair(
            KdcSetting setting) throws KrbException {
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
