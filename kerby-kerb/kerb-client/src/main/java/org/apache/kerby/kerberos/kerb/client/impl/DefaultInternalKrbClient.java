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
import org.apache.kerby.kerberos.kerb.client.ClientUtil;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.client.request.AsRequest;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

/**
 * A default krb client implementation.
 */
public class DefaultInternalKrbClient extends AbstractInternalKrbClient {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultInternalKrbClient.class);

    private DefaultKrbHandler krbHandler;
    private KrbTransport transport;

    public DefaultInternalKrbClient(KrbSetting krbSetting) {
        super(krbSetting);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init() throws KrbException {
        super.init();

        this.krbHandler = new DefaultKrbHandler();
        krbHandler.init(getContext());
    }

    private void doRequest(KdcRequest request) throws KrbException {

        List<String> kdcList = ClientUtil.getKDCList(getSetting());

        // tempKdc may include the port number
        Iterator<String> tempKdc = kdcList.iterator();
        if (!tempKdc.hasNext()) {
            throw new KrbException("Cannot get kdc for realm " + getSetting().getKdcRealm());
        }

        try {
            sendIfPossible(request, tempKdc.next(), getSetting(), false);
            LOG.info("Send to kdc success.");
        } catch (Exception first) {
            boolean ok = false;
            while (tempKdc.hasNext()) {
                try {
                    sendIfPossible(request, tempKdc.next(), getSetting(), true);
                    ok = true;
                    LOG.info("Send to kdc success.");
                    break;
                } catch (Exception ignore) {
                    LOG.info("ignore this kdc");
                }
            }
            if (!ok) {
                throw new KrbException("Failed to create transport", first);
            }
        } finally {
            if (transport != null) {
                transport.release();
            }
        }

    }

    private void sendIfPossible(KdcRequest request, String kdcString, KrbSetting setting,
                                boolean tryNextKdc)
        throws KrbException, IOException {

        TransportPair tpair = ClientUtil.getTransportPair(setting, kdcString);
        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(setting.getTimeout());
        transport = network.connect(tpair);
        request.setSessionData(transport);
        krbHandler.handleRequest(request, tryNextKdc);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected TgtTicket doRequestTgt(AsRequest tgtTktReq) throws KrbException {
        doRequest(tgtTktReq);

        return tgtTktReq.getTicket();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected SgtTicket doRequestSgt(TgsRequest ticketReq) throws KrbException {
        doRequest(ticketReq);

        return ticketReq.getSgt();
    }

}
