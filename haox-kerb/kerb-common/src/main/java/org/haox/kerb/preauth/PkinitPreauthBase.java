package org.haox.kerb.preauth;

import org.haox.kerb.spec.type.pa.PaDataType;

public class PkinitPreauthBase implements Preauth {

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
