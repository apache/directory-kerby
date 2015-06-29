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
package org.apache.kerby.kerberos.kerb.client.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * A default krb client implementation.
 */
public class DefaultInternalKrbClient extends AbstractInternalKrbClient {

    private DefaultKrbHandler krbHandler;
    private KrbTransport transport;

    public DefaultInternalKrbClient(KrbSetting krbSetting) {
        super(krbSetting);
    }

    @Override
    public void init() throws KrbException {
        super.init();

        this.krbHandler = new DefaultKrbHandler();
        krbHandler.init(getContext());

        InetSocketAddress tcpAddress = null, udpAddress = null;
        if (getSetting().allowTcp()) {
            tcpAddress = new InetSocketAddress(getSetting().getKdcHost(),
                    getSetting().getKdcTcpPort());
        }
        if (getSetting().allowUdp()) {
            udpAddress = new InetSocketAddress(getSetting().getKdcHost(),
                    getSetting().getKdcUdpPort());
        }

        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(getSetting().getTimeout());
        try {
            transport = network.connect(tcpAddress, udpAddress);
        } catch (IOException e) {
            throw new KrbException("Failed to create transport", e);
        }
    }

    @Override
    protected TgtTicket doRequestTgtTicket(AsRequest tgtTktReq) throws KrbException {
        tgtTktReq.setSessionData(transport);

        krbHandler.handleRequest(tgtTktReq);

        return tgtTktReq.getTicket();
    }

    @Override
    protected ServiceTicket doRequestServiceTicket(TgsRequest ticketReq) throws KrbException {
        ticketReq.setSessionData(transport);

        krbHandler.handleRequest(ticketReq);

        return ticketReq.getServiceTicket();
    }

}
