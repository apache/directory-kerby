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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.CacheableIdentityService;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.backend.MemoryIdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;

/**
 * Abstract KDC server implementation.
 */
public class AbstractInternalKdcServer implements InternalKdcServer {
    private boolean started;
    private final KdcConfig kdcConfig;
    private final BackendConfig backendConfig;
    private final KdcSetting kdcSetting;
    private IdentityBackend backend;
    private IdentityService identityService;

    public AbstractInternalKdcServer(KdcSetting kdcSetting) {
        this.kdcSetting = kdcSetting;
        this.kdcConfig = kdcSetting.getKdcConfig();
        this.backendConfig = kdcSetting.getBackendConfig();
    }

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

    protected IdentityService getIdentityService() {
        if (identityService == null) {
            if (backend instanceof MemoryIdentityBackend) { // Already in memory
                identityService = backend;
            } else {
                identityService = new CacheableIdentityService(
                        backendConfig, backend);
            }
        }
        return identityService;
    }

    @Override
    public void init() throws KrbException {
        backend = KdcUtil.getBackend(backendConfig);
    }

    @Override
    public void start() throws KrbException {
        try {
            doStart();
        } catch (Exception e) {
            throw new KrbException("Failed to start " + getServiceName(), e);
        }

        started = true;
    }

    public boolean enableDebug() {
        return kdcConfig.enableDebug();
    }

    @Override
    public IdentityBackend getIdentityBackend() {
        return backend;
    }

    protected void doStart() throws Exception {
        backend.start();
    }

    public void stop() throws KrbException {
        try {
            doStop();
        } catch (Exception e) {
            throw new KrbException("Failed to stop " + getServiceName(), e);
        }

        started = false;
    }

    protected void doStop() throws Exception {
        backend.stop();
    }
}
