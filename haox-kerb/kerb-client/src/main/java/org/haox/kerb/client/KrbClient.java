package org.haox.kerb.client;

import org.haox.event.Event;
import org.haox.event.EventHub;
import org.haox.event.EventWaiter;
import org.haox.kerb.client.event.KrbClientEvent;
import org.haox.kerb.client.event.KrbClientEventType;
import org.haox.kerb.client.request.*;
import org.haox.kerb.common.KrbErrorUtil;
import org.haox.kerb.common.KrbStreamingDecoder;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbError;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.haox.token.KerbToken;
import org.haox.transport.Connector;
import org.haox.transport.Transport;
import org.haox.transport.event.TransportEvent;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.tcp.TcpConnector;

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
     * @param principal
     * @param options
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, KrbOptions options) throws KrbException {
        if (options == null) options = new KrbOptions();

        AsRequestWithCert asRequest = new AsRequestWithCert(context);
        options.add(KrbOption.PKINIT_X509_ANONYMOUS);
        asRequest.setKrbOptions(options);

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
