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
package org.apache.kerby.kerberos.kerb.admin.server.kpasswd.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServerConfig;
import org.apache.kerby.kerberos.kerb.admin.server.kpasswd.PasswdServerSetting;
import org.apache.kerby.kerberos.kerb.identity.CacheableIdentityService;
import org.apache.kerby.kerberos.kerb.identity.IdentityService;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.MemoryIdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;

/**
 * Abstract Kpasswd passwd implementation.
 */
public class AbstractInternalPasswdServer implements InternalPasswdServer {
    private boolean started;
    private final PasswdServerConfig passwdConfig;
    private final BackendConfig backendConfig;
    private final PasswdServerSetting passwdSetting;
    private IdentityBackend backend;
    private IdentityService identityService;

    public AbstractInternalPasswdServer(PasswdServerSetting passwdSetting) {
        this.passwdSetting = passwdSetting;
        this.passwdConfig = passwdSetting.getPasswdServerConfig();
        this.backendConfig = passwdSetting.getBackendConfig();
    }

    @Override
    public PasswdServerSetting getSetting() {
        return passwdSetting;
    }

    public boolean isStarted() {
        return started;
    }

    protected String getServiceName() {
        return passwdConfig.getPasswdServiceName();
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
        return passwdConfig.enableDebug();
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
