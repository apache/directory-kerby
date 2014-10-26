package org.haox.kerb.client.as;

import org.haox.kerb.client.KdcRequest;
import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.preauth.PreauthContext;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.HostAddresses;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;

import java.util.List;

public class AsRequest extends KdcRequest {

    private PrincipalName clientPrincipal;
    private String password;
    private EncryptionKey clientKey;

    private AsReq asReq;

    public AsRequest(KrbContext context) {
        super(context);
        this.asReq = new AsReq();
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
    public KdcReq makeRequest() throws KrbException {
        KdcReqBody body = makeReqBody();

        asReq.setReqBody(body);
        asReq.setPaData(preparePaData());

        return asReq;
    }
}
