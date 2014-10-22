package org.haox.kerb.client.tgs;

import org.haox.kerb.client.KdcResponse;
import org.haox.kerb.client.KrbContext;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.kdc.EncTgsRepPart;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.kerb.spec.type.ticket.ServiceTicket;

public class TgsResponse extends KdcResponse {

    public TgsResponse(KrbContext context, TgsRep tgsRep, TgsRequest request) {
        super(context, tgsRep, request);
    }

    public TgsRep getTgsRep() {
        return (TgsRep) getKdcRep();
    }

    public TgsRequest getTgsRequest() {
        return (TgsRequest) getKdcRequest();
    }

    @Override
    public void handle() throws KrbException {
        TgsRep tgsRep = getTgsRep();
        EncTgsRepPart encTgsRepPart = EncryptionUtil.unseal(tgsRep.getEncryptedEncPart(),
                getTgsRequest().getSessionKey(),
                KeyUsage.TGS_REP_ENCPART_SESSKEY, EncTgsRepPart.class);

        tgsRep.setEncPart(encTgsRepPart);

        if (getKdcRequest().getChosenNonce() != encTgsRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }
    }

    public ServiceTicket getServiceTicket() {
        ServiceTicket serviceTkt = new ServiceTicket(getTgsRep().getTicket(),
                (EncTgsRepPart) getTgsRep().getEncPart());
        return serviceTkt;
    }
}
