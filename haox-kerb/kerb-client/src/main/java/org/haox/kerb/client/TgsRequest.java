package org.haox.kerb.client;

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
import org.haox.kerb.spec.type.kdc.*;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.ticket.ServiceTicket;
import org.haox.kerb.spec.type.ticket.TgtTicket;

public class TgsRequest extends KdcRequest {
    private TgtTicket tgt;

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
        ApOptions apOptions = new ApOptions();
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

    @Override
    public void processResponse(KdcRep kdcRep) throws KrbException {
        setKdcRep(kdcRep);

        TgsRep tgsRep = (TgsRep) getKdcRep();
        EncTgsRepPart encTgsRepPart = EncryptionUtil.unseal(tgsRep.getEncryptedEncPart(),
                getSessionKey(),
                KeyUsage.TGS_REP_ENCPART_SESSKEY, EncTgsRepPart.class);

        tgsRep.setEncPart(encTgsRepPart);

        if (getChosenNonce() != encTgsRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }
    }

    public ServiceTicket getServiceTicket() {
        ServiceTicket serviceTkt = new ServiceTicket(getKdcRep().getTicket(),
                (EncTgsRepPart) getKdcRep().getEncPart());
        return serviceTkt;
    }
}
