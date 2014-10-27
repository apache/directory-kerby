package org.haox.kerb.server;

import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.server.request.AsRequest;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.server.request.TgsRequest;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.TgsReq;
import org.haox.transport.MessageHandler;
import org.haox.transport.Transport;
import org.haox.transport.event.MessageEvent;
import org.haox.transport.tcp.TcpTransport;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class KdcHandler extends MessageHandler {

    private KdcContext kdcContext;
    private KdcConfig kdcConfig;
    private IdentityService identityService;
    private ReplayCheckService replayCheckService;
    private String kdcRealm;

    public void init() {
        kdcContext = new KdcContext();
        kdcContext.setConfig(kdcConfig);
        kdcContext.setKdcRealm(kdcRealm);
        kdcContext.setIdentityService(identityService);
        kdcContext.setReplayCache(replayCheckService);
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
        KdcRequest kdcRequest = null;

        KrbMessageType messageType = krbRequest.getMsgType();
        if (messageType == KrbMessageType.TGS_REQ) {
            kdcRequest = new TgsRequest((TgsReq) krbRequest);
        } else if (messageType == KrbMessageType.AS_REQ) {
            kdcRequest = new AsRequest((AsReq) krbRequest);
        }
        kdcRequest.setContext(kdcContext);

        InetSocketAddress clientAddress = transport.getRemoteAddress();
        kdcRequest.setClientAddress(clientAddress.getAddress());
        boolean isTcp = (transport instanceof TcpTransport);
        kdcRequest.isTcp(isTcp);

        kdcRequest.process();

        KrbMessage krbResponse = kdcRequest.getReply();
        KrbUtil.sendMessage(krbResponse, transport);
    }

}
