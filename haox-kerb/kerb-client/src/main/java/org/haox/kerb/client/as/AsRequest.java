package org.haox.kerb.client.as;

import org.haox.kerb.client.KdcRequest;
import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.preauth.PreauthContext;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;

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
}
