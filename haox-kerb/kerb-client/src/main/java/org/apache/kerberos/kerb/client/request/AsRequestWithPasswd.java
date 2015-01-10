package org.apache.kerberos.kerb.client.request;

import org.apache.kerberos.kerb.client.KrbContext;
import org.apache.kerberos.kerb.client.KrbOption;
import org.apache.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

public class AsRequestWithPasswd extends AsRequest {

    public AsRequestWithPasswd(KrbContext context) {
        super(context);

        setAllowedPreauth(PaDataType.ENC_TIMESTAMP);
    }

    public String getPassword() {
        return getKrbOptions().getStringOption(KrbOption.USER_PASSWD);
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        if (super.getClientKey() == null) {
            EncryptionKey tmpKey = EncryptionHandler.string2Key(getClientPrincipal().getName(),
                    getPassword(), getChosenEncryptionType());
            setClientKey(tmpKey);
        }
        return super.getClientKey();
    }
}
