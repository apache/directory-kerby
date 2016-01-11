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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin.impl;

import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerContext;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerSetting;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerUtil;
import org.apache.kerby.kerberos.kerb.transport.KdcNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A default admin admin implementation.
 */
public class DefaultInternalAdminServerImpl extends AbstractInternalAdminServer {
    private ExecutorService executor;
    private AdminServerContext adminContext;
    private KdcNetwork network;

    public DefaultInternalAdminServerImpl(AdminServerSetting adminSetting) {
        super(adminSetting);
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        prepareHandler();

        executor = Executors.newCachedThreadPool();

        network = new KdcNetwork() {
            @Override
            protected void onNewTransport(KrbTransport transport) {
                DefaultAdminServerHandler kdcHandler = 
                    new DefaultAdminServerHandler(adminContext, transport);
                executor.execute(kdcHandler);
            }
        };

        network.init();
        TransportPair tpair = AdminServerUtil.getTransportPair(getSetting());
        network.listen(tpair);
        network.start();
    }

    private void prepareHandler() {
        adminContext = new AdminServerContext(getSetting());
        adminContext.setIdentityService(getIdentityService());
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        network.stop();

        executor.shutdownNow();
    }
}
