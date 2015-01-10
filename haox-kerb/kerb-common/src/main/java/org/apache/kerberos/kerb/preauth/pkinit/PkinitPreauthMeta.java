package org.apache.kerberos.kerb.preauth.pkinit;

import org.apache.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

public class PkinitPreauthMeta implements PreauthPluginMeta {

    private static String NAME = "PKINIT";
    private static int VERSION = 1;
    private static PaDataType[] PA_TYPES = new PaDataType[] {
            PaDataType.PK_AS_REQ,
            PaDataType.PK_AS_REP,
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
