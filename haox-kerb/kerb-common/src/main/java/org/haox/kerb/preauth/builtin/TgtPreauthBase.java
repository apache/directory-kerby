package org.haox.kerb.preauth.builtin;

import org.haox.kerb.preauth.Preauth;
import org.haox.kerb.spec.type.pa.PaDataType;

/**
 * A faked preauth module for TGS request handling
 */
public class TgtPreauthBase implements Preauth {

    private static String NAME = "TGT_preauth";
    private static int VERSION = 1;
    private static PaDataType[] PA_TYPES = new PaDataType[] {
            PaDataType.TGS_REQ
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
