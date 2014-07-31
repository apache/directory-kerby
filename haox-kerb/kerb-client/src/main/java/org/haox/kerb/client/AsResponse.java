package org.haox.kerb.client;

import org.haox.kerb.crypto2.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.HostAddress;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.EncAsRepPart;
import org.haox.kerb.spec.type.kdc.EncKdcRepPart;
import org.haox.kerb.spec.type.ticket.TgtTicket;

import java.io.IOException;
import java.util.List;

public class AsResponse extends KdcResponse {

    public AsResponse(KrbContext context, AsRep asRep, AsRequest request) {
        super(context, asRep, request);
    }

    public AsRep getAsRep() {
        return (AsRep) getKdcRep();
    }

    @Override
    public void handle() throws KrbException  {
        if (! getKdcRequest().getClientPrincipal().equals(getKdcRep().getCname().getName())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_NAME_MISMATCH);
        }

        if (! getKdcRequest().getRealm().equals(getKdcRep().getCrealm())) {
            throw new KrbException(KrbErrorCode.WRONG_REALM);
        }

        byte[] decryptedData = getKdcRequest().decryptWithClientKey(getKdcRep().getEncryptedEncPart(), KeyUsage.AS_REP_ENC_PART_WITH_CKEY);
        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        try {
            encKdcRepPart.decode(decryptedData);
        } catch (IOException e) {
            throw new KrbException("Failed to decode EncAsRepPart", e);
        }
        getKdcRep().setEncPart(encKdcRepPart);

        if (getKdcRequest().getChosenNonce() != encKdcRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }

        if (! getKdcRequest().getServerPrincipal().equals(encKdcRepPart.getSname().getName())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SERVER_NOMATCH);
        }

        if (! getKdcRequest().getRealm().equals(encKdcRepPart.getSrealm())) {
            throw new KrbException("Realm didn't match");
        }

        List<HostAddress> requestHosts = getKdcRequest().getHostAddresses().getElements();
        if(! requestHosts.isEmpty()) {
            List<HostAddress> responseHosts = encKdcRepPart.getCaddr().getElements();
            for(HostAddress h : requestHosts) {
                if (! responseHosts.contains(h)) {
                    throw new KrbException("Unexpected client host");
                }
            }
        }
    }

    public TgtTicket getTicket() {
        TgtTicket TgtTicket = new TgtTicket(getAsRep().getTicket(),
                (EncAsRepPart) getAsRep().getEncPart(), getAsRep().getCname().getName());
        return TgtTicket;
    }
}
