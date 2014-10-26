package org.haox.kerb.client.as;

import org.haox.kerb.client.KdcResponse;
import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.preauth.PreauthContext;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.EncAsRepPart;
import org.haox.kerb.spec.type.kdc.EncKdcRepPart;
import org.haox.kerb.spec.type.ticket.TgtTicket;

import java.io.IOException;
import java.util.List;

public class AsResponse extends KdcResponse {

    public AsResponse(AsRep asRep) {
        super(asRep);
    }

    public AsRep getAsRep() {
        return (AsRep) getKdcRep();
    }

    @Override
    protected PreauthContext getPreauthContext() {
        return new PreauthContext() {

        };
    }

    @Override
    public void process() throws KrbException  {
        PrincipalName clientPrincipal = getKdcRep().getCname();
        String clientRealm = getKdcRep().getCrealm();
        clientPrincipal.setRealm(clientRealm);
        if (! clientPrincipal.equals(getKdcRequest().getClientPrincipal())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_NAME_MISMATCH);
        }

        byte[] decryptedData = getKdcRequest().decryptWithClientKey(getKdcRep().getEncryptedEncPart(),
                KeyUsage.AS_REP_ENCPART);
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

        PrincipalName serverPrincipal = encKdcRepPart.getSname();
        serverPrincipal.setRealm(encKdcRepPart.getSrealm());
        if (! serverPrincipal.equals(getKdcRequest().getServerPrincipal())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SERVER_NOMATCH);
        }

        HostAddresses hostAddresses = getKdcRequest().getHostAddresses();
        if (hostAddresses != null) {
            List<HostAddress> requestHosts = hostAddresses.getElements();
            if (!requestHosts.isEmpty()) {
                List<HostAddress> responseHosts = encKdcRepPart.getCaddr().getElements();
                for (HostAddress h : requestHosts) {
                    if (!responseHosts.contains(h)) {
                        throw new KrbException("Unexpected client host");
                    }
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
