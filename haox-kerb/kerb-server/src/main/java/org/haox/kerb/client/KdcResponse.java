package org.haox.kerb.client;

import org.haox.kerb.common.crypto.encryption.KeyUsage;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.HostAddress;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.kdc.EncAsRepPart;
import org.haox.kerb.spec.type.kdc.EncKdcRepPart;
import org.haox.kerb.spec.type.kdc.KdcRep;

import java.io.IOException;
import java.util.List;

public abstract class KdcResponse {
    private KrbContext context;
    private KdcRequest kdcRequest;
    private KdcRep kdcRep;

    public KdcResponse(KrbContext context, KdcRep kdcRep) {
        this.context = context;
        this.kdcRep = kdcRep;
    }

    public KdcRep getKdcRep() {
        return kdcRep;
    }

    public void handle() throws KrbException {
        if (! kdcRequest.getClientPrincipal().equals(kdcRep.getCname().getName())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_NAME_MISMATCH);
        }

        if (! kdcRequest.getRealm().equals(kdcRep.getCrealm())) {
            throw new KrbException(KrbErrorCode.WRONG_REALM);
        }

        byte[] decryptedData = kdcRequest.decrypt(kdcRep.getEncryptedEncPart(), KeyUsage.AS_REP_ENC_PART_WITH_CKEY);
        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        try {
            encKdcRepPart.decode(decryptedData);
        } catch (IOException e) {
            throw new KrbException("Failed to decode EncAsRepPart", e);
        }
        kdcRep.setEncPart(encKdcRepPart);

        if (kdcRequest.getChosenNonce() != encKdcRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }

        if (! kdcRequest.getServerPrincipal().equals(encKdcRepPart.getSname().getName())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SERVER_NOMATCH);
        }

        if (! kdcRequest.getRealm().equals(encKdcRepPart.getSrealm())) {
            throw new KrbException("Realm didn't match");
        }

        List<HostAddress> requestHosts = kdcRequest.getHostAddresses().getElements();
        if(! requestHosts.isEmpty()) {
            List<HostAddress> responseHosts = encKdcRepPart.getCaddr().getElements();
            for(HostAddress h : requestHosts) {
                if (! responseHosts.contains(h)) {
                    throw new KrbException("Unexpected client host");
                }
            }
        }
    }
}
