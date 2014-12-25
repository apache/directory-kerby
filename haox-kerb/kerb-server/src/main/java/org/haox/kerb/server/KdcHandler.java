package org.haox.kerb.server;

import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.server.preauth.PreauthHandler;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.server.request.AsRequest;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.server.request.TgsRequest;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.common.KrbMessage;
import org.haox.kerb.spec.common.KrbMessageType;
import org.haox.kerb.spec.kdc.AsReq;
import org.haox.kerb.spec.kdc.KdcReq;
import org.haox.kerb.spec.kdc.TgsReq;
import org.apache.haox.transport.MessageHandler;
import org.apache.haox.transport.Transport;
import org.apache.haox.transport.event.MessageEvent;
import org.apache.haox.transport.tcp.TcpTransport;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class KdcHandler extends MessageHandler {

    private List<String> kdcRealms = new ArrayList<String>(1);
    private Map<String, KdcContext> kdcContexts;

    private KdcConfig kdcConfig;
    private PreauthHandler preauthHandler;

    // TODO: per realm for below
    private IdentityService identityService;
    private ReplayCheckService replayCheckService;

    /**
     * Should be called when all the necessary properties are set
     */
    public void init() {
        loadKdcRealms();

        preauthHandler = new PreauthHandler();
        preauthHandler.init(kdcConfig);

        kdcContexts = new HashMap<String, KdcContext>(1);
        for (String realm : kdcRealms) {
            initRealmContext(realm);
        }
    }

    private void initRealmContext(String kdcRealm) {
        KdcContext kdcContext = new KdcContext();
        kdcContext.init(kdcConfig);
        kdcContext.setKdcRealm(kdcRealm);
        kdcContext.setPreauthHandler(preauthHandler);
        kdcContext.setIdentityService(identityService);
        kdcContext.setReplayCache(replayCheckService);

        kdcContexts.put(kdcRealm, kdcContext);
    }

    public void setKdcRealm(String realm) {
        this.kdcRealms.add(realm);
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
        if (messageType == KrbMessageType.TGS_REQ || messageType == KrbMessageType.AS_REQ) {
            KdcReq kdcReq = (KdcReq) krbRequest;
            String realm = getRequestRealm(kdcReq);
            if (realm == null || !kdcContexts.containsKey(realm)) {
                throw new KrbException("Invalid realm from kdc request: " + realm);
            }

            KdcContext kdcContext = kdcContexts.get(realm);
            if (messageType == KrbMessageType.TGS_REQ) {
                kdcRequest = new TgsRequest((TgsReq) kdcReq, kdcContext);
            } else if (messageType == KrbMessageType.AS_REQ) {
                kdcRequest = new AsRequest((AsReq) kdcReq, kdcContext);
            }
        }

        InetSocketAddress clientAddress = transport.getRemoteAddress();
        kdcRequest.setClientAddress(clientAddress.getAddress());
        boolean isTcp = (transport instanceof TcpTransport);
        kdcRequest.isTcp(isTcp);

        kdcRequest.process();

        KrbMessage krbResponse = kdcRequest.getReply();
        KrbUtil.sendMessage(krbResponse, transport);
    }

    private void loadKdcRealms() {
        if (kdcRealms.isEmpty()) {
            kdcRealms.add(kdcConfig.getKdcRealm());
        }
    }

    private String getRequestRealm(KdcReq kdcReq) {
        String realm = kdcReq.getReqBody().getRealm();
        if (realm == null && kdcReq.getReqBody().getCname() != null) {
            realm = kdcReq.getReqBody().getCname().getRealm();
        }
        if (realm == null || realm.isEmpty()) {
            realm = "NULL-KDC-REALM";
        }
        return realm;
    }
}
