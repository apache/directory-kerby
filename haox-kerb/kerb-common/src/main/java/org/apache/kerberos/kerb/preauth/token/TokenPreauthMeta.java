package org.apache.kerberos.kerb.preauth.token;

import org.apache.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

public class TokenPreauthMeta implements PreauthPluginMeta {

    private static String NAME = "TokenPreauth";
    private static int VERSION = 1;
    private static PaDataType[] PA_TYPES = new PaDataType[] {
            PaDataType.TOKEN_CHALLENGE,
            PaDataType.TOKEN_REQUEST
    };

    @Override
    public String getName() {
        return NAME;
    }

    public int getVersion() {
        return VERSION;
    }

    public PaDataType[] getPaTypes() {
        return PA_TYPES;
    }
}
