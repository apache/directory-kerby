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
package org.apache.kerby.kerberos.kerb.server.impl.event;

import org.apache.kerby.event.EventHub;
import org.apache.kerby.kerberos.kerb.common.KrbStreamingDecoder;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.impl.AbstractInternalKdcServer;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.transport.Network;

/**
 * Event based KDC server.
 */
public class EventBasedKdcServer extends AbstractInternalKdcServer {

    private KdcHandler kdcHandler;
    private EventHub eventHub;

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        prepareHandler();

        this.eventHub = new EventHub();

        eventHub.register(kdcHandler);

        Network network = new Network();
        network.setStreamingDecoder(new KrbStreamingDecoder());
        eventHub.register(network);

        eventHub.start();
        network.tcpListen(getKdcSetting().getKdcHost(),
                getKdcSetting().getKdcTcpPort());
        if (getKdcSetting().allowUdp()) {
            network.udpListen(getKdcSetting().getKdcHost(),
                    getKdcSetting().getKdcUdpPort());
        }
    }

    private void prepareHandler() {
        KdcContext kdcContext = new KdcContext(getKdcSetting());
        kdcContext.setIdentityService(getBackend());
        PreauthHandler preauthHandler = new PreauthHandler();
        preauthHandler.init(kdcContext.getConfig());
        kdcContext.setPreauthHandler(preauthHandler);

        this.kdcHandler = new KdcHandler(kdcContext);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        eventHub.stop();
    }
}
