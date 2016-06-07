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
package org.apache.kerby.kerberos.kdc.impl;

import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.server.impl.AbstractInternalKdcServer;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * A Netty based KDC server implementation.
 */
public class NettyKdcServerImpl extends AbstractInternalKdcServer {
    private ExecutorService executor;
    private KdcContext kdcContext;
    private NettyKdcNetwork network;
    private static final Logger LOG = LoggerFactory.getLogger(NettyKdcServerImpl.class);

    public NettyKdcServerImpl(KdcSetting kdcSetting) {
        super(kdcSetting);
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        prepareHandler();

        executor = Executors.newCachedThreadPool();

        network = new NettyKdcNetwork();

        network.init(kdcContext);

        InetSocketAddress tcpAddress, udpAddress = null;
        tcpAddress = new InetSocketAddress(getSetting().getKdcHost(),
                getSetting().getKdcTcpPort());
        if (getSetting().allowUdp()) {
            udpAddress = new InetSocketAddress(getSetting().getKdcHost(),
                    getSetting().getKdcUdpPort());
        }
        network.listen(tcpAddress, udpAddress);
        network.start();
        LOG.info("Netty kdc server started.");
    }

    private void prepareHandler() {
        kdcContext = new KdcContext(getSetting());
        kdcContext.setIdentityService(getIdentityService());
        PreauthHandler preauthHandler = new PreauthHandler();
        preauthHandler.init();
        kdcContext.setPreauthHandler(preauthHandler);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        network.stop();

        executor.shutdown();

        try {
            boolean terminated = false;
            do {
                // wait until the pool has terminated
                terminated = executor.awaitTermination(60, TimeUnit.SECONDS);
            } while (!terminated);
        } catch (InterruptedException e) {
            executor.shutdownNow();
            LOG.warn("waitForTermination interrupted");
        }
        LOG.info("Netty kdc server stopped.");
    }
}
