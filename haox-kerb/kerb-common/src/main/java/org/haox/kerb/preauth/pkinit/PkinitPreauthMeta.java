package org.haox.kerb.preauth.pkinit;

import org.haox.kerb.preauth.PreauthPluginMeta;
import org.haox.kerb.spec.pa.PaDataType;

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
