package org.haox.kerb.client;

import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.common.KrbUtil;
import org.haox.kerb.crypto.encryption.KeyUsage;
import org.haox.kerb.spec.KrbException;
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

    private ApOptions apOptions = new ApOptions();

    private EncryptionKey sessionKey;

    private KdcOptions kdcOptions = new KdcOptions();

    public TgsRequest(KrbContext context, TgtTicket tgtTicket) {
        super(context);
        this.tgt = tgtTicket;
    }

    public void setSessionKey(EncryptionKey sessionKey) {
        this.sessionKey = sessionKey;
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        this.kdcOptions = kdcOptions;
    }

    @Override
    public KdcReq makeKdcRequest() throws KrbException {
        Authenticator authenticator = new Authenticator();
        authenticator.setCname(new PrincipalName(tgt.getClientPrincipal()));
        authenticator.setCrealm(tgt.getRealm());

        long ctime = System.currentTimeMillis();
        authenticator.setCtime(new KerberosTime(ctime));
        authenticator.setCusec(0);

        if(sessionKey == null) {
            sessionKey = tgt.getSessionKey();
        }
        authenticator.setSubKey(sessionKey);

        EncryptedData authnData = encodingAndEncryptWithSessionKey(authenticator,
                KeyUsage.TGS_REQ_PA_TGS_REQ_PADATA_AP_REQ_TGS_SESS_KEY);

        ApReq apReq = new ApReq();
        apReq.setEncryptedAuthenticator(authnData);
        apReq.setTicket(tgt.getTicket());
        apReq.setApOptions(apOptions);

        KdcReqBody tgsReqBody = new KdcReqBody();
        tgsReqBody.setKdcOptions(getKdcOptions());
        tgsReqBody.setRealm(KrbUtil.extractRealm(getRealm()));
        tgsReqBody.setTill(new KerberosTime(ctime + getTicketTillTime()));
        int nonce = generateNonce();
        tgsReqBody.setNonce(nonce);
        setChosenNonce(nonce);
        tgsReqBody.setEtypes(getEtypes());

        PrincipalName principalName = new PrincipalName(getServerPrincipal());
        tgsReqBody.setSname(principalName);

        TgsReq tgsReq = new TgsReq();
        tgsReq.setReqBody(tgsReqBody);

        PaDataEntry authnHeader = new PaDataEntry();
        authnHeader.setPaDataType(PaDataType.TGS_REQ);
        authnHeader.setPaDataValue(apReq.encode());
        tgsReq.addPaData(authnHeader);

        return tgsReq;
    }

    protected EncryptedData encodingAndEncryptWithSessionKey(Asn1Type value, KeyUsage usage) throws KrbException {
        byte[] encodedData = value.encode();
        return getContext().getCipherHandler().encrypt(sessionKey, encodedData, usage);
    }

    protected byte[] decryptWithSessionKey(EncryptedData data, KeyUsage usage) throws KrbException {
        return getContext().getCipherHandler().decrypt(sessionKey, data, usage);
    }
}
