package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.preauth.PreauthContext;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.*;
import org.haox.kerb.spec.type.ticket.TgtTicket;

import java.io.IOException;
import java.util.List;

public class AsRequest extends KdcRequest {

    private PrincipalName clientPrincipal;
    private String password;
    private EncryptionKey clientKey;

    public AsRequest(KrbContext context) {
        super(context);
    }

    @Override
    protected PreauthContext getPreauthContext() {
        return new PreauthContext() {
            public EncryptionKey getAsKey() throws KrbException {
                return getClientKey();
            }

            public void setAsKey(EncryptionKey asKey) {
                setClientKey(asKey);
            }
        };
    }

    public PrincipalName getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(PrincipalName clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setClientKey(EncryptionKey clientKey) {
        this.clientKey = clientKey;
    }

    public EncryptionKey getClientKey() throws KrbException {
        if (clientKey == null) {
            clientKey = EncryptionHandler.string2Key(getClientPrincipal().getName(),
                    getPassword(), getChosenEncryptionType());
        }
        return clientKey;
    }

    @Override
    public void process() throws KrbException {
        KdcReqBody body = makeReqBody();

        AsReq asReq = new AsReq();
        asReq.setReqBody(body);
        asReq.setPaData(preparePaData());

        setKdcReq(asReq);
    }

    @Override
    public void processResponse(KdcRep kdcRep) throws KrbException  {
        setKdcRep(kdcRep);

        PrincipalName clientPrincipal = getKdcRep().getCname();
        String clientRealm = getKdcRep().getCrealm();
        clientPrincipal.setRealm(clientRealm);
        if (! clientPrincipal.equals(getClientPrincipal())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_NAME_MISMATCH);
        }

        byte[] decryptedData = decryptWithClientKey(getKdcRep().getEncryptedEncPart(),
                KeyUsage.AS_REP_ENCPART);
        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        try {
            encKdcRepPart.decode(decryptedData);
        } catch (IOException e) {
            throw new KrbException("Failed to decode EncAsRepPart", e);
        }
        getKdcRep().setEncPart(encKdcRepPart);

        if (getChosenNonce() != encKdcRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }

        PrincipalName serverPrincipal = encKdcRepPart.getSname();
        serverPrincipal.setRealm(encKdcRepPart.getSrealm());
        if (! serverPrincipal.equals(getServerPrincipal())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SERVER_NOMATCH);
        }

        HostAddresses hostAddresses = getHostAddresses();
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
        TgtTicket TgtTicket = new TgtTicket(getKdcRep().getTicket(),
                (EncAsRepPart) getKdcRep().getEncPart(), getKdcRep().getCname().getName());
        return TgtTicket;
    }

}
