package org.haox.kerb.client.tgs;

import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.client.KdcRequest;
import org.haox.kerb.client.KrbContext;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.kdc.KdcOptions;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;
import org.haox.kerb.spec.type.kdc.TgsReq;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.ticket.TgtTicket;

public class TgsRequest extends KdcRequest {
    private TgtTicket tgt;

    private ApOptions apOptions = new ApOptions();

    private KdcOptions kdcOptions = new KdcOptions();

    public TgsRequest(KrbContext context, TgtTicket tgtTicket) {
        super(context);
        this.tgt = tgtTicket;
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        this.kdcOptions = kdcOptions;
    }

    public EncryptionKey getSessionKey() {
        return tgt.getSessionKey();
    }

    @Override
    public KdcReq makeKdcRequest() throws KrbException {
        TgsReq tgsReq = new TgsReq();

        KdcReqBody tgsReqBody = makeReqBody();
        tgsReq.setReqBody(tgsReqBody);

        ApReq apReq = makeApReq();
        PaDataEntry authnHeader = new PaDataEntry();
        authnHeader.setPaDataType(PaDataType.TGS_REQ);
        authnHeader.setPaDataValue(apReq.encode());
        tgsReq.addPaData(authnHeader);

        return tgsReq;
    }

    private ApReq makeApReq() throws KrbException {
        ApReq apReq = new ApReq();

        Authenticator authenticator = makeAuthenticator();
        EncryptionKey sessionKey = tgt.getSessionKey();
        EncryptedData authnData = EncryptionUtil.seal(authenticator,
                sessionKey, KeyUsage.TGS_REQ_AUTH);
        apReq.setEncryptedAuthenticator(authnData);

        apReq.setTicket(tgt.getTicket());
        apReq.setApOptions(apOptions);

        return apReq;
    }

    private Authenticator makeAuthenticator() {
        Authenticator authenticator = new Authenticator();
        authenticator.setCname(new PrincipalName(tgt.getClientPrincipal()));
        authenticator.setCrealm(tgt.getRealm());

        long ctime = System.currentTimeMillis();
        authenticator.setCtime(new KerberosTime(ctime));
        authenticator.setCusec(0);

        EncryptionKey sessionKey = tgt.getSessionKey();
        authenticator.setSubKey(sessionKey);

        return authenticator;
    }
}
