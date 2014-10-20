package org.haox.kerb.server;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.server.as.AsContext;
import org.haox.kerb.server.as.AsService;
import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.server.tgs.TgsContext;
import org.haox.kerb.server.tgs.TgsService;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.TgsReq;
import org.haox.transport.MessageHandler;
import org.haox.transport.Transport;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.tcp.TcpTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class KdcHandler extends MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(KdcHandler.class);

    private KdcConfig kdcConfig;
    private KdcService asService;
    private KdcService tgsService;
    private IdentityService identityService;
    private String kdcRealm;

    public void init() {
        this.asService = new AsService();
        this.tgsService = new TgsService();

        asService.setIdentityService(identityService);
        tgsService.setIdentityService(identityService);
    }

    public void setKdcRealm(String realm) {
        this.kdcRealm = realm;
    }

    public void setConfig(KdcConfig config) {
        this.kdcConfig = config;
    }

    public void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }

    @Override
    protected void handleMessage(MessageEvent event) throws Exception {
        ByteBuffer message = event.getMessage();
        Transport transport = event.getTransport();

        KrbMessage krbRequest = KrbUtil.decodeMessage(message);

        KrbMessage krbResponse = null;
        KdcContext kdcContext = null;
        KdcService service = null;

        KrbMessageType messageType = krbRequest.getMsgType();
        if (messageType == KrbMessageType.TGS_REQ) {
            kdcContext = new TgsContext();
            service = tgsService;
        } else if (messageType == KrbMessageType.AS_REQ) {
            kdcContext = new AsContext();
            service = asService;
        }

        kdcContext.setConfig(kdcConfig);
        kdcContext.setKdcRealm(kdcRealm);

        InetSocketAddress clientAddress = transport.getRemoteAddress();
        kdcContext.setClientAddress(clientAddress.getAddress());
        boolean isTcp = (transport instanceof TcpTransport);
        kdcContext.isTcp(isTcp);

        kdcContext.setRequest((KdcReq) krbRequest);
        service.serve(kdcContext);

        krbResponse = kdcContext.getReply();
        KrbUtil.sendMessage(krbResponse, transport);
    }

}
