package org.haox.kerb.client;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.kerb.client.as.AsRequest;
import org.haox.kerb.client.as.AsResponse;
import org.haox.kerb.client.event.KrbClientEvent;
import org.haox.kerb.client.event.KrbClientEventType;
import org.haox.kerb.client.tgs.TgsRequest;
import org.haox.kerb.client.tgs.TgsResponse;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.transport.Transport;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.event.TransportEventType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

public class KrbHandler extends AbstractEventHandler {
    private static final Logger logger = LoggerFactory.getLogger(KrbHandler.class);

    private KdcRequest theKdcRequest;

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
            theKdcRequest = (KdcRequest) event.getEventData();
            processTgtTicketRequest((AsRequest) theKdcRequest);
        } else if (eventType == KrbClientEventType.TKT_INTENT) {
            theKdcRequest = (KdcRequest) event.getEventData();
            processServiceTicketRequest((TgsRequest) theKdcRequest);
        } else if (event.getEventType() == TransportEventType.INBOUND_MESSAGE) {
            handleMessage((MessageEvent) event);
        }
    }

    private void processTgtTicketRequest(AsRequest kdcRequest) throws KrbException {
        KdcReq kdcReq = kdcRequest.makeKdcRequest();
        sendKdcReq(kdcReq, kdcRequest.getTransport());
    }

    private void processServiceTicketRequest(TgsRequest kdcRequest) throws KrbException {
        KdcReq kdcReq = kdcRequest.makeKdcRequest();
        sendKdcReq(kdcReq, kdcRequest.getTransport());
    }

    private void sendKdcReq(KdcReq kdcReq, Transport transport) {
        int bodyLen = kdcReq.encodingLength();
        ByteBuffer buffer = ByteBuffer.allocate(bodyLen + 4);
        buffer.putInt(bodyLen);
        kdcReq.encode(buffer);
        buffer.flip();
        transport.sendMessage(buffer);
    }

    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        KrbMessage kdcRep = KrbCodec.decodeMessage(message);
        KdcResponse kdcResponse = null;

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            kdcResponse = new AsResponse(theKdcRequest.getContext(),
                    (AsRep) kdcRep, (AsRequest) theKdcRequest);
            kdcResponse.handle();
            dispatch(KrbClientEvent.createTgtResultEvent((AsResponse) kdcResponse));
        } else if (messageType == KrbMessageType.TGS_REP) {
            kdcResponse = new TgsResponse(theKdcRequest.getContext(),
                    (TgsRep) kdcRep, (TgsRequest) theKdcRequest);
            kdcResponse.handle();
            dispatch(KrbClientEvent.createTktResultEvent((TgsResponse) kdcResponse));
        }
    }
}
