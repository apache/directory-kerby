package org.apache.kerberos.kerb.client;

import org.apache.haox.event.AbstractEventHandler;
import org.apache.haox.event.Event;
import org.apache.haox.event.EventType;
import org.apache.kerberos.kerb.client.event.KrbClientEvent;
import org.apache.kerberos.kerb.client.event.KrbClientEventType;
import org.apache.kerberos.kerb.client.preauth.PreauthHandler;
import org.apache.kerberos.kerb.client.request.AsRequest;
import org.apache.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerberos.kerb.common.KrbUtil;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.KrbMessage;
import org.apache.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.haox.transport.Transport;
import org.apache.haox.transport.event.MessageEvent;
import org.apache.haox.transport.event.TransportEventType;

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
