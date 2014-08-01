package org.haox.kerb.client;

import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.kdc.EncTgsRepPart;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.kerb.spec.type.ticket.ServiceTicket;

import java.io.IOException;

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
        byte[] decryptedData = getTgsRequest().decryptWithSessionKey(getTgsRep().getEncryptedEncPart(), KeyUsage.TGS_REP_ENCPART_SESSKEY);
        EncTgsRepPart encTgsRepPart = new EncTgsRepPart();
        try {
            encTgsRepPart.decode(decryptedData);
        } catch (IOException e) {
            throw new KrbException("Failed to decode encTgsRepPart", e);
        }
        getTgsRep().setEncPart(encTgsRepPart);

        if (getKdcRequest().getChosenNonce() != encTgsRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }
    }

    public ServiceTicket getServiceTicket() {
        ServiceTicket serviceTkt = new ServiceTicket(getTgsRep().getTicket(), (EncTgsRepPart) getTgsRep().getEncPart());
        return serviceTkt;
    }
}
