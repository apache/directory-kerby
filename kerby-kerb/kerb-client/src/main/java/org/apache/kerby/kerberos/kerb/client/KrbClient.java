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
package org.apache.kerby.kerberos.kerb.client;

import org.apache.kerby.event.Event;
import org.apache.kerby.event.EventHub;
import org.apache.kerby.event.EventWaiter;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.client.event.KrbClientEvent;
import org.apache.kerby.kerberos.kerb.client.event.KrbClientEventType;
import org.apache.kerby.kerberos.kerb.client.request.*;
import org.apache.kerby.kerberos.kerb.common.KrbErrorUtil;
import org.apache.kerby.kerberos.kerb.common.KrbStreamingDecoder;
import org.apache.kerby.kerberos.kerb.KrbErrorException;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.KrbError;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.token.KerbToken;
import org.apache.kerby.transport.Connector;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.TransportEvent;
import org.apache.kerby.transport.event.TransportEventType;
import org.apache.kerby.transport.tcp.TcpConnector;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * A krb client API for applications to interact with KDC
 */
public class KrbClient {

    private EventHub eventHub;
    private EventWaiter eventWaiter;
    private Transport transport;

    private KrbHandler krbHandler;
    private KrbContext context;
    private KrbConfig config;

    /**
     *
     * @param kdcHost
     * @param kdcPort
     */
    public KrbClient(String kdcHost, short kdcPort) {
        this(new KrbConfig());

        setKdcHost(kdcHost);
        setKdcPort(kdcPort);
    }

    public KrbClient(KrbConfig config) {
        this.config = config;
        this.context = new KrbContext();
        context.init(config);
    }

    /**
     * Set KDC realm for ticket request
     * @param realm
     */
    public void setKdcRealm(String realm) {
        context.setKdcRealm(realm);
    }

    /**
     *
     * @param kdcHost
     */
    public void setKdcHost(String kdcHost) {
        context.setKdcHost(kdcHost);
    }

    /**
     *
     * @param kdcPort
     */
    public void setKdcPort(short kdcPort) {
        context.setKdcPort(kdcPort);
    }

    /**
     * Set time out for connection
     * @param timeout in seconds
     */
    public void setTimeout(long timeout) {
        context.setTimeout(timeout);
    }

    public void init() {
        this.krbHandler = new KrbHandler();
        krbHandler.init(context);

        this.eventHub = new EventHub();
        eventHub.register(krbHandler);

        Connector connector = new TcpConnector(new KrbStreamingDecoder());
        eventHub.register(connector);

        eventWaiter = eventHub.waitEvent(
                TransportEventType.NEW_TRANSPORT,
                KrbClientEventType.TGT_RESULT,
                KrbClientEventType.TKT_RESULT
        );

        eventHub.start();

        connector.connect(context.getKdcHost(), context.getKdcPort());
        Event event = eventWaiter.waitEvent(TransportEventType.NEW_TRANSPORT);
        transport = ((TransportEvent) event).getTransport();
    }

    /**
     * Attempt to request a TGT and you'll be prompted to input a credential.
     * Whatever credential requested to provide depends on KDC admin configuration.
     * @param options
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        AsRequest asRequest = new AsRequest(context);
        asRequest.setKrbOptions(options);
        return requestTgtTicket(principal, asRequest);
    }

    /**
     * Request a TGT with user plain credential
     * @param principal
     * @param password
     * @param options
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, String password,
                                      KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        AsRequest asRequest = new AsRequestWithPasswd(context);
        options.add(KrbOption.USER_PASSWD, password);
        asRequest.setKrbOptions(options);
        return requestTgtTicket(principal, asRequest);
    }

    /**
     * Request a TGT with user x509 certificate credential
     * @param principal
     * @param certificate
     * @param privateKey
     * @param options
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, Certificate certificate,
                                      PrivateKey privateKey, KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        AsRequestWithCert asRequest = new AsRequestWithCert(context);
        options.add(KrbOption.PKINIT_X509_CERTIFICATE, certificate);
        options.add(KrbOption.PKINIT_X509_PRIVATE_KEY, privateKey);
        asRequest.setKrbOptions(options);
        return requestTgtTicket(principal, asRequest);
    }

    /**
     * Request a TGT with using Anonymous PKINIT
     * @param options
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        AsRequestWithCert asRequest = new AsRequestWithCert(context);
        options.add(KrbOption.PKINIT_X509_ANONYMOUS);
        asRequest.setKrbOptions(options);

        String principal = AsRequestWithCert.ANONYMOUS_PRINCIPAL;
        return requestTgtTicket(principal, asRequest);
    }

    /**
     * Request a TGT with user token credential
     * @param principal
     * @param token
     * @param options
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, KerbToken token,
                                      KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        AsRequestWithToken asRequest = new AsRequestWithToken(context);
        options.add(KrbOption.TOKEN_USER_ID_TOKEN, token);
        asRequest.setKrbOptions(options);
        return requestTgtTicket(principal, asRequest);
    }

    /**
     * Request a service ticket targeting for a server with user plain credentials
     * @param clientPrincipal
     * @param password
     * @param serverPrincipal
     * @param options
     * @return
     * @throws KrbException
     */
    public ServiceTicket requestServiceTicket(String clientPrincipal, String password,
                                              String serverPrincipal, KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        TgtTicket tgt = requestTgtTicket(clientPrincipal, password, options);
        return requestServiceTicket(tgt, serverPrincipal, options);
    }

    /**
     * Request a service ticket targeting for a server with an user Access Token
     * @param clientPrincipal
     * @param token
     * @param serverPrincipal
     * @param options
     * @return
     * @throws KrbException
     */
    public ServiceTicket requestServiceTicket(String clientPrincipal, KerbToken token,
                                              String serverPrincipal, KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        TgtTicket tgt = requestTgtTicket(clientPrincipal, token, options);
        return requestServiceTicket(tgt, serverPrincipal, options);
    }

    private TgtTicket requestTgtTicket(String clientPrincipal, AsRequest tgtTktReq) throws KrbException {
        tgtTktReq.setClientPrincipal(new PrincipalName(clientPrincipal));
        tgtTktReq.setTransport(transport);

        try {
            return doRequestTgtTicket(tgtTktReq);
        } catch(KrbErrorException e) {
            KrbError krbError = e.getKrbError();
            if (krbError.getErrorCode() == KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED) {
                try {
                    tgtTktReq.setEncryptionTypes(KrbErrorUtil.getEtypes(krbError));
                } catch (IOException ioe) {
                    throw new KrbException("Failed to decode and get etypes from krbError", ioe);
                }
                tgtTktReq.getPreauthContext().setPreauthRequired(true);
                return requestTgtTicket(clientPrincipal, tgtTktReq);
            }
            throw e;
        }
    }

    private TgtTicket doRequestTgtTicket(AsRequest tgtTktReq) throws KrbException {
        eventHub.dispatch(KrbClientEvent.createTgtIntentEvent(tgtTktReq));
        Event resultEvent = null;
        try {
            resultEvent = eventWaiter.waitEvent(KrbClientEventType.TGT_RESULT,
                    context.getTimeout(), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new KrbException("Network timeout", e);
        }
        AsRequest asResponse = (AsRequest) resultEvent.getEventData();

        return asResponse.getTicket();
    }

    /**
     * Request a service ticket with a TGT targeting for a server
     * @param tgt
     * @param serverPrincipal
     * @return
     * @throws KrbException
     */
    public ServiceTicket requestServiceTicket(TgtTicket tgt, String serverPrincipal,
                                              KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        TgsRequest ticketReq = new TgsRequest(context, tgt);
        ticketReq.setServerPrincipal(new PrincipalName(serverPrincipal));
        ticketReq.setTransport(transport);

        eventHub.dispatch(KrbClientEvent.createTktIntentEvent(ticketReq));
        Event resultEvent = null;
        try {
            resultEvent = eventWaiter.waitEvent(KrbClientEventType.TKT_RESULT,
                    context.getTimeout(), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new KrbException("Network timeout", e);
        }
        TgsRequest tgsResponse = (TgsRequest) resultEvent.getEventData();

        return tgsResponse.getServiceTicket();
    }

}
