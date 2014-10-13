package org.haox.kerb.server;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.kerb.spec.type.kdc.TgsReq;
import org.haox.transport.MessageHandler;
import org.haox.transport.Transport;
import org.haox.transport.event.MessageEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

public class KdcHandler extends MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(KdcHandler.class);

    private KrbMessage processKrbMessage(KrbMessage message) throws KrbException {
        KrbMessage response = null;

        KrbMessageType messageType = message.getMsgType();
        if (messageType == KrbMessageType.AP_REQ) {
            response = processAsReq((AsReq) message);
        } else if (messageType == KrbMessageType.AP_REQ) {
            response = processTgsReq((TgsReq) message);
        }

        return response;
    }

    private AsRep processAsReq(AsReq message) throws KrbException {
        AsRep asRep = new AsRep();

        asRep.setCname(message.getReqBody().getCname());
        asRep.setCrealm(message.getReqBody().getRealm());

        return asRep;
    }

    private TgsRep processTgsReq(TgsReq message) throws KrbException {
        TgsRep tgsRep = new TgsRep();

        tgsRep.setCname(message.getReqBody().getCname());
        tgsRep.setCrealm(message.getReqBody().getRealm());

        return tgsRep;
    }

    @Override
    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        Transport transport = event.getTransport();

        int bodyLen = message.getInt();
        assert (message.remaining() >= bodyLen);

        KrbMessage krbRequest = null;
        krbRequest = KrbCodec.decodeMessage(message);

        KrbMessage krbResponse = null;
        krbResponse = processKrbMessage(krbRequest);

        ByteBuffer response = ByteBuffer.wrap(krbResponse.encode());
        transport.sendMessage(response);
    }
}
