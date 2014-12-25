package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.common.EncryptionKey;
import org.haox.kerb.spec.pa.PaDataType;

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
