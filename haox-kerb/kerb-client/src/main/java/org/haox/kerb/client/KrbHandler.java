package org.haox.kerb.client;

import org.haox.event.AbstractEventHandler;
import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.kerb.client.event.KrbClientEvent;
import org.haox.kerb.client.event.KrbClientEventType;
import org.haox.kerb.client.preauth.PreauthHandler;
import org.haox.kerb.client.request.AsRequest;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.client.request.TgsRequest;
import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.common.KrbMessage;
import org.haox.kerb.spec.common.KrbMessageType;
import org.haox.kerb.spec.kdc.KdcRep;
import org.haox.kerb.spec.kdc.KdcReq;
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

        if (eventType == KrbClientEventType.TGT_INTENT ||
                eventType == KrbClientEventType.TKT_INTENT) {
            KdcRequest kdcRequest = (KdcRequest) event.getEventData();
            handleKdcRequest(kdcRequest);
        } else if (event.getEventType() == TransportEventType.INBOUND_MESSAGE) {
            handleMessage((MessageEvent) event);
        }
    }

    protected void handleKdcRequest(KdcRequest kdcRequest) throws KrbException {
        kdcRequest.process();
        KdcReq kdcReq = kdcRequest.getKdcReq();
        Transport transport = kdcRequest.getTransport();
        transport.setAttachment(kdcRequest);
        KrbUtil.sendMessage(kdcReq, transport);
    }

    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        KrbMessage kdcRep = KrbUtil.decodeMessage(message);

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            KdcRequest kdcRequest = (KdcRequest) event.getTransport().getAttachment();
            kdcRequest.processResponse((KdcRep) kdcRep);
            dispatch(KrbClientEvent.createTgtResultEvent((AsRequest) kdcRequest));
        } else if (messageType == KrbMessageType.TGS_REP) {
            KdcRequest kdcRequest = (KdcRequest) event.getTransport().getAttachment();
            kdcRequest.processResponse((KdcRep) kdcRep);
            dispatch(KrbClientEvent.createTktResultEvent((TgsRequest) kdcRequest));
        }
    }
}
