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
package org.apache.kerby.kerberos.kerb.server.impl;

import org.apache.kerby.KOptions;
import org.apache.kerby.config.Conf;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.backend.MemoryIdentityBackend;
import org.apache.kerby.kerberos.kerb.server.*;

import java.io.File;
import java.io.IOException;

/**
 * Abstract KDC server implementation.
 */
public class AbstractInternalKdcServer implements InternalKdcServer {

    private boolean started;

    private KdcConfig kdcConfig;
    private Conf backendConfig;
    private KdcSetting kdcSetting;
    private IdentityBackend backend;

    @Override
    public KdcSetting getSetting() {
        return kdcSetting;
    }

    public boolean isStarted() {
        return started;
    }

    protected String getServiceName() {
        return kdcConfig.getKdcServiceName();
    }

    protected IdentityBackend getBackend() {
        return backend;
    }

    @Override
    public void init(KOptions startupOptions) {
        try {
            initConfig(startupOptions);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load configurations", e);
        }

        kdcSetting = new KdcSetting(startupOptions, kdcConfig);

        initBackend();
    }

    /**
     * Prepare kdc and backend config, loading kdc.conf and backend.conf.
     * It can be override to add more configuration resources.
     */
    private void initConfig(KOptions startupOptions) throws IOException {
        if (startupOptions.contains(KdcServerOption.KDC_CONFIG)) {
            kdcConfig = (KdcConfig) startupOptions.getOptionValue(
                    KdcServerOption.KDC_CONFIG);
        } else {
            kdcConfig = new KdcConfig();
            File confDir = startupOptions.getDirOption(KdcServerOption.CONF_DIR);
            if (confDir != null && confDir.exists()) {
                File kdcConfFile = new File(confDir, "kdc.conf");
                if (kdcConfFile.exists()) {
                    kdcConfig.addIniConfig(kdcConfFile);
                }
            }
        }

        if (startupOptions.contains(KdcServerOption.BACKEND_CONFIG)) {
            backendConfig = (BackendConfig) startupOptions.getOptionValue(
                    KdcServerOption.BACKEND_CONFIG);
        } else {
            backendConfig = new BackendConfig();
            File confDir = startupOptions.getDirOption(KdcServerOption.CONF_DIR);
            if (confDir != null && confDir.exists()) {
                File backendConfFile = new File(confDir, "backend.conf");
                if (backendConfFile.exists()) {
                    backendConfig.addIniConfig(backendConfFile);
                }
            }
        }
    }

    private void initBackend() {
        String backendClassName = backendConfig.getString(
                KdcConfigKey.KDC_IDENTITY_BACKEND);
        if (backendClassName == null) {
            backendClassName = MemoryIdentityBackend.class.getCanonicalName();
        }

        Class backendClass = null;
        try {
            backendClass = Class.forName(backendClassName);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Failed to load backend class: "
                    + backendClassName);
        }

        try {
            backend = (IdentityBackend) backendClass.newInstance();
        } catch (InstantiationException e) {
            throw new RuntimeException("Failed to create backend: "
                    + backendClassName);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Failed to create backend: "
                    + backendClassName);
        }

        backend.setConfig(backendConfig);
        backend.initialize();
    }

    @Override
    public void start() {
        try {
            doStart();
        } catch (Exception e) {
            throw new RuntimeException("Failed to start " + getServiceName(), e);
        }

        started = true;
    }

    public boolean enableDebug() {
        return kdcConfig.enableDebug();
    }

    @Override
    public IdentityService getIdentityService() {
        return backend;
    }

    protected void doStart() throws Exception {
        backend.start();
    }

    public void stop() {
        try {
            doStop();
        } catch (Exception e) {
            throw new RuntimeException("Failed to stop " + getServiceName());
        }

        started = false;
    }

    protected void doStop() throws Exception {
        backend.stop();
    }
}
