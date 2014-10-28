package org.haox.kerb.client;

import org.haox.event.Event;
import org.haox.event.EventHub;
import org.haox.event.EventWaiter;
import org.haox.kerb.client.event.KrbClientEvent;
import org.haox.kerb.client.event.KrbClientEventType;
import org.haox.kerb.client.request.AsRequest;
import org.haox.kerb.client.request.CertAsRequest;
import org.haox.kerb.client.request.TgsRequest;
import org.haox.kerb.client.request.TokenAsRequest;
import org.haox.kerb.common.KrbStreamingDecoder;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbError;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.haox.kerb.spec.type.x509.Certificate;
import org.haox.token.KerbToken;
import org.haox.transport.Connector;
import org.haox.transport.Transport;
import org.haox.transport.event.TransportEvent;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.tcp.TcpConnector;

import java.io.IOException;
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
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, String password) throws KrbException {
        AsRequest asRequest = new AsRequest(context);
        asRequest.setClientPrincipal(new PrincipalName(principal));
        asRequest.setPassword(password);
        asRequest.setTransport(transport);
        return requestTgtTicket(asRequest);
    }

    /**
     * Request a TGT with user x509 certificate credential
     * @param principal
     * @param certificate
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, Certificate certificate) throws KrbException {
        CertAsRequest asRequest = new CertAsRequest(context);
        asRequest.setClientPrincipal(new PrincipalName(principal));
        asRequest.setCertificate(certificate);
        asRequest.setTransport(transport);
        return requestTgtTicket(asRequest);
    }

    /**
     * Request a TGT with user token credential
     * @param principal
     * @param token
     * @return
     * @throws KrbException
     */
    public TgtTicket requestTgtTicket(String principal, KerbToken token) throws KrbException {
        TokenAsRequest asRequest = new TokenAsRequest(context);
        asRequest.setClientPrincipal(new PrincipalName(principal));
        asRequest.setToken(token);
        asRequest.setTransport(transport);
        return requestTgtTicket(asRequest);
    }

    /**
     * Request a service ticket targeting for a server with user plain credentials
     * @param clientPrincipal
     * @param password
     * @param serverPrincipal
     * @return
     * @throws KrbException
     */
    public ServiceTicket requestServiceTicket(String clientPrincipal, String password,
                                              String serverPrincipal) throws KrbException {
        TgtTicket tgt = requestTgtTicket(clientPrincipal, password);
        return requestServiceTicket(tgt, serverPrincipal);
    }

    /**
     * Request a service ticket targeting for a server with an user Access Token
     * @param clientPrincipal
     * @param token
     * @param serverPrincipal
     * @return
     * @throws KrbException
     */
    public ServiceTicket requestServiceTicket(String clientPrincipal, KerbToken token,
                                              String serverPrincipal) throws KrbException {
        TgtTicket tgt = requestTgtTicket(clientPrincipal, token);
        return requestServiceTicket(tgt, serverPrincipal);
    }

    private TgtTicket requestTgtTicket(AsRequest tgtTktReq) throws KrbException {
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
                tgtTktReq.setPreauthRequired(true);
                return requestTgtTicket(tgtTktReq);
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
    public ServiceTicket requestServiceTicket(TgtTicket tgt, String serverPrincipal) throws KrbException {
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
