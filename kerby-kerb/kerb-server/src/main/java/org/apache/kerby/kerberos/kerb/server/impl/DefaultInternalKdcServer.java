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

import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.transport.KdcNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A default KDC server implementation.
 */
public class DefaultInternalKdcServer extends AbstractInternalKdcServer {
    private ExecutorService executor;
    private KdcContext kdcContext;
    private KdcNetwork network;

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        prepareHandler();

        executor = Executors.newCachedThreadPool();

        network = new KdcNetwork() {
            @Override
            protected void onNewTransport(KrbTransport transport) {
                DefaultKdcHandler kdcHandler = new DefaultKdcHandler(kdcContext, transport);
                executor.execute(kdcHandler);
            }
        };

        network.init();

        InetSocketAddress tcpAddress, udpAddress = null;
        tcpAddress = new InetSocketAddress(getSetting().getKdcHost(),
                getSetting().getKdcTcpPort());
        if (getSetting().allowUdp()) {
            udpAddress = new InetSocketAddress(getSetting().getKdcHost(),
                    getSetting().getKdcUdpPort());
        }
        network.listen(tcpAddress, udpAddress);
        network.start();
    }

    private void prepareHandler() {
        kdcContext = new KdcContext(getSetting());
        kdcContext.setIdentityService(getBackend());
        PreauthHandler preauthHandler = new PreauthHandler();
        preauthHandler.init();
        kdcContext.setPreauthHandler(preauthHandler);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        network.stop();

        executor.shutdownNow();
    }
}
