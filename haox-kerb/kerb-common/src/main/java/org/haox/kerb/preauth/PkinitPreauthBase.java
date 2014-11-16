package org.haox.kerb.preauth;

import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.List;

public class PkinitPreauthBase implements Preauth {

    private static String NAME = "PKINIT";
    private static int VERSION = 1;
    private static PaDataType[] PA_TYPES = new PaDataType[] {
            PaDataType.PK_AS_REQ,
            PaDataType.PK_AS_REP,
    };

    protected PkinitContext context;

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
