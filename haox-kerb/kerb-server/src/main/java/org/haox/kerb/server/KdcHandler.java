package org.haox.kerb.server;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.server.as.AsContext;
import org.haox.kerb.server.as.AsService;
import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.server.tgs.TgsService;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.TgsReq;
import org.haox.transport.MessageHandler;
import org.haox.transport.Transport;
import org.haox.transport.event.MessageEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;

public class KdcHandler extends MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(KdcHandler.class);

    private KdcConfig kdcConfig;
    private KdcService asService;
    private KdcService tgsService;
    private IdentityService identityService;

    public void init() {
        this.asService = new AsService();
        this.tgsService = new TgsService();

        asService.setIdentityService(identityService);
        tgsService.setIdentityService(identityService);
    }

    public void setConfig(KdcConfig config) {
        this.kdcConfig = config;
    }

    public void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }

    private KrbMessage processKrbMessage(KrbMessage message) throws KrbException {
        KrbMessage response = null;

        KrbMessageType messageType = message.getMsgType();
        if (messageType == KrbMessageType.AS_REQ) {
            response = processAsReq((AsReq) message);
        } else if (messageType == KrbMessageType.TGS_REQ) {
            response = processTgsReq((TgsReq) message);
        }

        return response;
    }

    private KrbMessage processAsReq(AsReq message) throws KrbException {
        KdcContext kdcContext = new AsContext();
        kdcContext.setConfig(kdcConfig);
        kdcContext.setRequest(message);

        asService.serve(kdcContext);
        return kdcContext.getReply();
    }

    private KrbMessage processTgsReq(TgsReq message) throws KrbException {
        KdcContext kdcContext = new AsContext();
        kdcContext.setConfig(kdcConfig);
        kdcContext.setRequest(message);

        asService.serve(kdcContext);
        return kdcContext.getReply();
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
