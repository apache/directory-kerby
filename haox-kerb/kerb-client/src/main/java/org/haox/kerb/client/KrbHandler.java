package org.haox.kerb.client;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.kerb.client.as.AsRequest;
import org.haox.kerb.client.as.AsResponse;
import org.haox.kerb.client.event.KrbClientEvent;
import org.haox.kerb.client.event.KrbClientEventType;
import org.haox.kerb.client.preauth.PreauthHandler;
import org.haox.kerb.client.tgs.TgsRequest;
import org.haox.kerb.client.tgs.TgsResponse;
import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.transport.Transport;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.event.TransportEventType;

import java.nio.ByteBuffer;

public class KrbHandler extends AbstractEventHandler {

    private KrbContext context;
    private PreauthHandler preauthHandler;

    public void init(KrbContext context) {
        this.context = context;
        preauthHandler = new PreauthHandler();
        preauthHandler.init(context);
    }

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                TransportEventType.INBOUND_MESSAGE,
                KrbClientEventType.TGT_INTENT,
                KrbClientEventType.TKT_INTENT
        };
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        EventType eventType = event.getEventType();

        if (eventType == KrbClientEventType.TGT_INTENT) {
            KdcRequest kdcRequest = (KdcRequest) event.getEventData();
            processTgtTicketRequest((AsRequest) kdcRequest);
        } else if (eventType == KrbClientEventType.TKT_INTENT) {
            KdcRequest kdcRequest = (KdcRequest) event.getEventData();
            processServiceTicketRequest((TgsRequest) kdcRequest);
        } else if (event.getEventType() == TransportEventType.INBOUND_MESSAGE) {
            handleMessage((MessageEvent) event);
        }
    }

    private void processTgtTicketRequest(AsRequest kdcRequest) throws KrbException {
        kdcRequest.setPreauthHandler(preauthHandler);
        KdcReq kdcReq = kdcRequest.makeRequest();
        Transport transport = kdcRequest.getTransport();
        transport.setAttachment(kdcRequest);
        KrbUtil.sendMessage(kdcReq, transport);
    }

    private void processServiceTicketRequest(TgsRequest kdcRequest) throws KrbException {
        kdcRequest.setPreauthHandler(preauthHandler);
        KdcReq kdcReq = kdcRequest.makeRequest();
        Transport transport = kdcRequest.getTransport();
        transport.setAttachment(kdcRequest);
        KrbUtil.sendMessage(kdcReq, transport);
    }

    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        KrbMessage kdcRep = KrbUtil.decodeMessage(message);
        KdcResponse kdcResponse = null;

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            kdcResponse = new AsResponse((AsRep) kdcRep);
            KdcRequest kdcRequest = (KdcRequest) event.getTransport().getAttachment();
            kdcResponse.setKdcRequest(kdcRequest);
            kdcResponse.process();
            dispatch(KrbClientEvent.createTgtResultEvent((AsResponse) kdcResponse));
        } else if (messageType == KrbMessageType.TGS_REP) {
            kdcResponse = new TgsResponse((TgsRep) kdcRep);
            KdcRequest kdcRequest = (KdcRequest) event.getTransport().getAttachment();
            kdcResponse.setKdcRequest(kdcRequest);
            kdcResponse.process();
            dispatch(KrbClientEvent.createTktResultEvent((TgsResponse) kdcResponse));
        }
    }
}
