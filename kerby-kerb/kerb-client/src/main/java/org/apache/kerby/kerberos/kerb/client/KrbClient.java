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
import org.apache.kerby.kerberos.kerb.KrbErrorException;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.event.KrbClientEvent;
import org.apache.kerby.kerberos.kerb.client.event.KrbClientEventType;
import org.apache.kerby.kerberos.kerb.client.request.*;
import org.apache.kerby.kerberos.kerb.common.KrbErrorUtil;
import org.apache.kerby.kerberos.kerb.common.KrbStreamingDecoder;
import org.apache.kerby.kerberos.kerb.spec.base.KrbError;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.transport.Network;
import org.apache.kerby.transport.Transport;
import org.apache.kerby.transport.event.TransportEvent;
import org.apache.kerby.transport.event.TransportEventType;

import java.io.File;
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
    private String kdcHost;
    private int kdcTcpPort;
    private Boolean allowUdp;
    private int kdcUdpPort;
    private KrbConfig krbConfig;
    private File confDir;

    /**
     * Default constructor.
     */
    public KrbClient() {
        this(new KrbConfig());
    }

    /**
     * Construct a KrbClient with host and port. The port can be TCP, UDP or
     * both, but TCP will try first.
     * @param kdcHost
     * @param kdcPort
     */
    public KrbClient(String kdcHost, int kdcPort) {
        this(new KrbConfig());

        setKdcHost(kdcHost);
        setKdcTcpPort(kdcPort);
        setKdcUdpPort(kdcPort);
    }

    /**
     * Construct with prepared KrbConfig
     * @param krbConfig
     */
    public KrbClient(KrbConfig krbConfig) {
        this.krbConfig = krbConfig;
        this.context = new KrbContext();
        context.init(krbConfig);
    }

    /**
     * Prepare krb config, loading krb5.conf.
     * It can be override to add more configuration resources.
     *
     * @throws IOException
     */
    protected void initConfig() throws IOException {
        if (confDir == null) {
            confDir = new File("/etc/"); // for Linux. TODO: fix for Win etc.
        }
        if (confDir != null && confDir.exists()) {
            File kdcConfFile = new File(confDir, "krb5.conf");
            if (kdcConfFile.exists()) {
                krbConfig.addIniConfig(kdcConfFile);
            }
        }
    }

    /**
     * Set the conf dir
     * @param file
     */
    public void setConfDir(File file) throws IOException {
        confDir = file;
    }

    /**
     * Set KDC realm for ticket request
     * @param realm
     */
    public void setKdcRealm(String realm) {
        context.setKdcRealm(realm);
    }

    private String getKdcHost() {
        if (kdcHost != null) {
            return kdcHost;
        }
        return krbConfig.getKdcHost();
    }

    private int getKdcTcpPort() {
        if (kdcTcpPort > 0) {
            return kdcTcpPort;
        }
        return krbConfig.getKdcTcpPort();
    }

    private boolean allowUdp() {
        if (allowUdp != null) {
            return allowUdp;
        }
        return krbConfig.allowKdcUdp();
    }

    private int getKdcUdpPort() {
        if (kdcUdpPort > 0) {
            return kdcUdpPort;
        }
        return krbConfig.getKdcUdpPort();
    }

    /**
     * Set KDC host.
     * @param kdcHost
     */
    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    /**
     * Set KDC tcp port.
     * @param kdcTcpPort
     */
    public void setKdcTcpPort(int kdcTcpPort) {
        this.kdcTcpPort = kdcTcpPort;
    }

    /**
     * Set to allow UDP or not.
     * @param allowUdp
     */
    public void setAllowUdp(boolean allowUdp) {
        this.allowUdp = allowUdp;
    }

    /**
     * Set KDC udp port. Only makes sense when allowUdp is set.
     * @param kdcUdpPort
     */
    public void setKdcUdpPort(int kdcUdpPort) {
        this.kdcUdpPort = kdcUdpPort;
    }

    /**
     * Set time out for connection
     * @param timeout in seconds
     */
    public void setTimeout(long timeout) {
        context.setTimeout(timeout);
    }

    public void init() {
        try {
            initConfig();
        } catch (IOException e) {
            throw new RuntimeException("Failed to load config", e);
        }

        this.krbHandler = new KrbHandler();
        krbHandler.init(context);

        this.eventHub = new EventHub();
        eventHub.register(krbHandler);

        Network network = new Network();
        network.setStreamingDecoder(new KrbStreamingDecoder());
        eventHub.register(network);

        eventWaiter = eventHub.waitEvent(
                TransportEventType.NEW_TRANSPORT,
                KrbClientEventType.TGT_RESULT,
                KrbClientEventType.TKT_RESULT
        );

        eventHub.start();

        network.tcpConnect(getKdcHost(), getKdcTcpPort());
        if (allowUdp()) {
            network.udpConnect(getKdcHost(), getKdcUdpPort());
        }
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
    public TgtTicket requestTgtTicket(String principal,
                                      KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

        AsRequest asRequest;
        if (options.contains(KrbOption.USE_KEYTAB)) {
            asRequest = new AsRequestWithKeytab(context);
        } else {
            asRequest = new AsRequest(context);
        }

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
                                      KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

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
    public TgtTicket requestTgtTicket(
            String principal, Certificate certificate, PrivateKey privateKey,
            KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

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
    public TgtTicket requestTgtTicket(KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

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
    public TgtTicket requestTgtTicket(String principal, AuthToken token,
                                      KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

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
    public ServiceTicket requestServiceTicket(
            String clientPrincipal, String password, String serverPrincipal,
            KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

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
    public ServiceTicket requestServiceTicket(
            String clientPrincipal, AuthToken token, String serverPrincipal,
            KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

        TgtTicket tgt = requestTgtTicket(clientPrincipal, token, options);
        return requestServiceTicket(tgt, serverPrincipal, options);
    }

    private TgtTicket requestTgtTicket(String clientPrincipal,
                                       AsRequest tgtTktReq) throws KrbException {
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
        Event resultEvent;
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
                                              KOptions options) throws KrbException {
        if (options == null) {
            options = new KOptions();
        }

        TgsRequest ticketReq = new TgsRequest(context, tgt);
        ticketReq.setServerPrincipal(new PrincipalName(serverPrincipal));
        ticketReq.setTransport(transport);

        eventHub.dispatch(KrbClientEvent.createTktIntentEvent(ticketReq));
        Event resultEvent;
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
