package org.haox.kerb.client;

import org.apache.directory.shared.kerberos.codec.types.PrincipalNameType;
import org.haox.kerb.common.crypto.encryption.KeyUsage;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcOptions;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;
import org.haox.kerb.spec.type.kdc.TgsReq;
import org.haox.kerb.spec.type.ticket.TgtTicket;

public class TgsRequest extends KdcRequest {
    private TgsReq tgsReq;
    private TgtTicket tgt;

    private String serverPrincipal;

    private ApOptions apOptions = new ApOptions();

    private EncryptionKey subSessionKey;

    private KdcOptions kdcOptions = new KdcOptions();

    public TgsRequest(KrbContext context, TgtTicket tgtTicket) {
        super(context);
        this.tgt = tgtTicket;
    }

    public void setSubSessionKey(EncryptionKey subSessionKey) {
        this.subSessionKey = subSessionKey;
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        this.kdcOptions = kdcOptions;
    }

    @Override
    public KdcReq makeKdcRequest() {
        // session key
        EncryptionKey sessionKey = tgt.getSessionKey();
        Authenticator authenticator = new Authenticator();
        authenticator.setCname(new PrincipalName(serviceTicketReq.getTgt().getClientName(), PrincipalNameType.KRB_NT_PRINCIPAL));
        authenticator.setCrealm(serviceTicketReq.getTgt().getRealm());
        authenticator.setCtime(new KerberosTime());
        authenticator.setCusec(0);

        if(serviceTicketReq.getSubSessionKey() != null) {
            sessionKey = serviceTicketReq.getSubSessionKey();
            authenticator.setSubKey(sessionKey);
        }

        EncryptedData authnData = cipherTextHandler.encrypt(sessionKey, getEncoded(authenticator), KeyUsage.TGS_REQ_PA_TGS_REQ_PADATA_AP_REQ_TGS_SESS_KEY);

        ApReq apReq = new ApReq();

        apReq.setAuthenticator(authnData);
        apReq.setTicket(serviceTicketReq.getTgt().getTicket());

        apReq.setApOptions(serviceTicketReq.getApOptions());

        KdcReqBody tgsReqBody = new KdcReqBody();
        tgsReqBody.setKdcOptions(serviceTicketReq.getKdcOptions());
        tgsReqBody.setRealm(KrbUtil.extractRealm(serverPrincipal));
        tgsReqBody.setTill(getDefaultTill());
        int currentNonce = nonceGenerator.nextInt();
        tgsReqBody.setNonce(currentNonce);
        tgsReqBody.setEtype(config.getEncryptionTypes());

        PrincipalName principalName = new PrincipalName(KrbUtil.extractName(serverPrincipal), KerberosPrincipal.KRB_NT_SRV_HST);
        tgsReqBody.setSname(principalName);

        TgsReq tgsReq = new TgsReq();
        tgsReq.setKdcReqBody(tgsReqBody);

        PaData authnHeader = new PaData();
        authnHeader.setPaDataType(PaDataType.PA_TGS_REQ);
        authnHeader.setPaDataValue(getEncoded(apReq));

        tgsReq.addPaData(authnHeader);

        return tgsReq;
    }
}
