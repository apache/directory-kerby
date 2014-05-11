package org.haox.kerb.client;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbError;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;

public class KrbClient {
    private static final Logger LOG = LoggerFactory.getLogger(KrbClient.class);

    private KrbContext context;

    private KrbConfig config;
    private EncryptionType usedEtype;

    public KrbClient(String kdcHost, int kdcPort) {
        this.context = new KrbContext();
        context.setKdcHost(kdcHost);
        context.setKdcPort(kdcPort);
    }

    public KrbClient(KrbConfig config) {
        this.config = config;
        this.context = new KrbContext();
        context.setConfig(config);
    }

    public TgtTicket requestTgtTicket(String principal, String password) throws KrbException {
        context.setClientPrincipal(principal);
        context.setPassword(password);
        AsRequest asRequest = new AsRequest(context);
        return requestTgtTicket(asRequest);
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
        KrbMessage respMsg;
        try {
            respMsg = sendAndReceive(tgtTktReq);
        } catch (IOException e) {
            throw new KrbException(KrbErrorCode.KRB_TIMEOUT);
        }
        if (respMsg instanceof KrbError) {
            throw new KrbErrorException((KrbError) respMsg);
        }

        AsRep asRep = (AsRep) respMsg;
        AsResponse asResponse = new AsResponse(context, asRep);
        asResponse.handle();
        return asResponse.getTicket();
    }

    public ServiceTicket requestServiceTicket(TgtTicket tgt, String serverPrincipal) throws KrbException {
        context.setServerPrincipal(serverPrincipal);
        TgsRequest ticketReq = new TgsRequest(context, tgt);

        KrbMessage respMsg;
        try {
            respMsg = sendAndReceive(ticketReq);
        } catch (IOException e) {
            throw new KrbException(KrbErrorCode.KRB_TIMEOUT);
        }
        if (respMsg instanceof KrbError) {
            throw new KrbErrorException((KrbError) respMsg);
        }

        TgsRep tgsRep = (TgsRep) respMsg;
        TgsResponse tgsResponse = new TgsResponse(context, tgsRep);
        tgsResponse.handle();
        return tgsResponse.getServiceTicket();
    }

    /*
    public void run() throws Exception {
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new KrbClientHandler());

            // Make the connection attempt.
            ChannelFuture f = b.connect(kdcHost, kdcPort).sync();

            // Wait until the connection is closed.
            f.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    } */

    private KrbMessage sendAndReceive(KdcRequest kdcRequest) throws IOException {
        KdcReq kdcReq = kdcRequest.makeKdcRequest();
        ByteBuffer buffer = ByteBuffer.wrap(kdcReq.encode());

        ByteBuffer respData = null;//sendAndReceive(buffer);
        return KrbCodec.decodeMessage(respData);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3) {
            System.err.println(
                    "Usage: " + KrbClient.class.getSimpleName() +
                            " <kdcHost> <kdcPort>");
            return;
        }

        final String host = args[0];
        final int port = Integer.parseInt(args[1]);
        KrbClient krbClnt = new KrbClient(host, port);
    }
}
