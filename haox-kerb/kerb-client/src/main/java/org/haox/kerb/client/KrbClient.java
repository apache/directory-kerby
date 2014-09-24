package org.haox.kerb.client;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbConstant;
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
        this(new KrbConfig());

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
        context.setServerPrincipal(makeTgsPrincipal());
        AsRequest asRequest = new AsRequest(context);
        return requestTgtTicket(asRequest);
    }

    private String makeTgsPrincipal() {
        return KrbConstant.TGS_PRINCIPAL + "@EXAMPLE.COM";
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
        respMsg = sendAndReceive(tgtTktReq);
        if (respMsg instanceof KrbError) {
            throw new KrbErrorException((KrbError) respMsg);
        }

        AsRep asRep = (AsRep) respMsg;
        AsResponse asResponse = new AsResponse(context, asRep, tgtTktReq);
        asResponse.handle();
        return asResponse.getTicket();
    }

    public ServiceTicket requestServiceTicket(TgtTicket tgt, String serverPrincipal) throws KrbException {
        context.setServerPrincipal(serverPrincipal);
        TgsRequest ticketReq = new TgsRequest(context, tgt);

        KrbMessage respMsg;
        respMsg = sendAndReceive(ticketReq);
        if (respMsg instanceof KrbError) {
            throw new KrbErrorException((KrbError) respMsg);
        }

        TgsRep tgsRep = (TgsRep) respMsg;
        TgsResponse tgsResponse = new TgsResponse(context, tgsRep, ticketReq);
        tgsResponse.handle();
        return tgsResponse.getServiceTicket();
    }

    private KrbMessage sendAndReceive(KdcRequest kdcRequest) throws KrbException {
        KdcReq kdcReq = kdcRequest.makeKdcRequest();
        ByteBuffer buffer = ByteBuffer.wrap(kdcReq.encode());

        ByteBuffer respData = null;//sendAndReceive(buffer);
        try {
            return KrbCodec.decodeMessage(respData);
        } catch (IOException e) {
            throw new KrbException("Failed to decode krb message");
        }
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
