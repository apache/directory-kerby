package org.haox.kerb.client.tgs;

import org.haox.kerb.client.KdcRequest;
import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.preauth.PreauthContext;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.KeyUsage;
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

    @Override
    protected PreauthContext getPreauthContext() {
        return new PreauthContext() {
            public EncryptionKey getAsKey() throws KrbException {
                return getClientKey();
            }
        };
    }

    public PrincipalName getClientPrincipal() {
        return tgt.getClientPrincipal();
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        return getSessionKey();
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        this.kdcOptions = kdcOptions;
    }

    public EncryptionKey getSessionKey() {
        return tgt.getSessionKey();
    }

    @Override
    public void process() throws KrbException {
        TgsReq tgsReq = new TgsReq();

        KdcReqBody tgsReqBody = makeReqBody();
        tgsReq.setReqBody(tgsReqBody);
        //tgsReq.setPaData(preparePaData());

        ApReq apReq = makeApReq();
        PaDataEntry authnHeader = new PaDataEntry();
        authnHeader.setPaDataType(PaDataType.TGS_REQ);
        authnHeader.setPaDataValue(apReq.encode());
        tgsReq.addPaData(authnHeader);

        setKdcReq(tgsReq);
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
        authenticator.setCname(getClientPrincipal());
        authenticator.setCrealm(tgt.getRealm());

        authenticator.setCtime(KerberosTime.now());
        authenticator.setCusec(0);

        EncryptionKey sessionKey = tgt.getSessionKey();
        authenticator.setSubKey(sessionKey);

        return authenticator;
    }
}
