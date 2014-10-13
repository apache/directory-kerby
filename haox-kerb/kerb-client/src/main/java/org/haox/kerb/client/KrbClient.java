package org.haox.kerb.client;

import org.haox.event.Event;
import org.haox.event.EventHub;
import org.haox.event.EventWaiter;
import org.haox.kerb.client.as.AsRequest;
import org.haox.kerb.client.as.AsResponse;
import org.haox.kerb.client.event.KrbClientEvent;
import org.haox.kerb.client.event.KrbClientEventType;
import org.haox.kerb.client.tgs.TgsRequest;
import org.haox.kerb.client.tgs.TgsResponse;
import org.haox.kerb.common.KrbStreamingDecoder;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbError;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.haox.transport.Connector;
import org.haox.transport.Transport;
import org.haox.transport.event.TransportEvent;
import org.haox.transport.event.TransportEventType;
import org.haox.transport.tcp.TcpConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * A krb client API for applications to interact with KDC
 */
public class KrbClient {
    private static final Logger LOG = LoggerFactory.getLogger(KrbClient.class);

    private EventHub eventHub;
    private EventWaiter eventWaiter;
    private Transport transport;

    private KrbContext context;
    private KrbConfig config;
    private EncryptionType usedEtype;
    private String kdcHost;
    private short kdcPort;

    public KrbClient(String kdcHost, short kdcPort) {
        this(new KrbConfig());

        setKdcHost(kdcHost);
        setKdcPort(kdcPort);
    }

    public KrbClient(KrbConfig config) {
        this.config = config;
        this.context = new KrbContext();
        context.setConfig(config);
    }

    public void init() {
        this.eventHub = new EventHub();
        eventHub.register(new KrbHandler());

        Connector connector = new TcpConnector(new KrbStreamingDecoder());
        eventHub.register(connector);

        eventWaiter = eventHub.waitEvent(
                TransportEventType.NEW_TRANSPORT,
                KrbClientEventType.TGT_RESULT,
                KrbClientEventType.TKT_RESULT
        );

        eventHub.start();

        connector.connect(getKdcHost(), getKdcPort());
        Event event = eventWaiter.waitEvent(TransportEventType.NEW_TRANSPORT);
        transport = ((TransportEvent) event).getTransport();
    }

    public String getKdcHost() {
        if (kdcHost != null) {
            return kdcHost;
        }
        return config.getKdcHost();
    }

    public void setKdcHost(String kdcHost) {
        this.kdcHost = kdcHost;
    }

    public short getKdcPort() {
        if (kdcPort > 0) {
            return kdcPort;
        }
        return config.getKdcPort();
    }

    public void setKdcPort(short kdcPort) {
        this.kdcPort = kdcPort;
    }

    public TgtTicket requestTgtTicket(String principal, String password) throws KrbException {
        context.setClientPrincipal(principal);
        context.setPassword(password);
        context.setServerPrincipal(makeTgsPrincipal());

        AsRequest asRequest = new AsRequest(context);
        asRequest.setTransport(transport);
        return requestTgtTicket(asRequest);
    }

    private String makeTgsPrincipal() {
        return KrbConstant.TGS_PRINCIPAL + "@EXAMPLE.COM";
    }

    public ServiceTicket requestServiceTicket(String clientPrincipal, String password,
                                              String serverPrincipal) throws KrbException {
        TgtTicket tgt = requestTgtTicket(clientPrincipal, password);
        return requestServiceTicket(tgt, serverPrincipal);
    }

    private TgtTicket requestTgtTicket(AsRequest tgtTktReq) throws KrbException {
        TgtTicket tgt = null;

        try {
            return doRequestTgtTicket(tgtTktReq);
        } catch(KrbErrorException e) {
            KrbError krbError = e.getKrbError();
            if (krbError.getErrorCode() == KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED) {
                try {
                    tgtTktReq.setEtypes(KrbErrorUtil.getEtypes(krbError));
                } catch (IOException ioe) {
                    throw new KrbException("Failed to decode and get etypes from krbError", ioe);
                }
                tgtTktReq.setPreAuthEnabled(true);
                return requestTgtTicket(tgtTktReq);
            }
            throw e;
        }
    }

    private TgtTicket doRequestTgtTicket(AsRequest tgtTktReq) throws KrbException {
        eventHub.dispatch(KrbClientEvent.createTgtIntentEvent(tgtTktReq));
        Event resultEvent = null;
        try {
            resultEvent = eventWaiter.waitEvent(KrbClientEventType.TGT_RESULT, 20, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new KrbException("Network timeout", e);
        }
        AsResponse asResponse = (AsResponse) resultEvent.getEventData();

        return asResponse.getTicket();
    }

    public ServiceTicket requestServiceTicket(TgtTicket tgt, String serverPrincipal) throws KrbException {
        context.setServerPrincipal(serverPrincipal);
        TgsRequest ticketReq = new TgsRequest(context, tgt);
        ticketReq.setTransport(transport);

        eventHub.dispatch(KrbClientEvent.createTktIntentEvent(ticketReq));
        Event resultEvent = null;
        try {
            resultEvent = eventWaiter.waitEvent(KrbClientEventType.TKT_RESULT, 20, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new KrbException("Network timeout", e);
        }
        TgsResponse tgsResponse = (TgsResponse) resultEvent.getEventData();

        return tgsResponse.getServiceTicket();
    }

}
