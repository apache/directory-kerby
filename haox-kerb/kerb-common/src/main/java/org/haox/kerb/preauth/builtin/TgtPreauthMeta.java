package org.haox.kerb.preauth.builtin;

import org.haox.kerb.preauth.PreauthPluginMeta;
import org.haox.kerb.spec.pa.PaDataType;

/**
 * A faked preauth module for TGS request handling
 */
public class TgtPreauthMeta implements PreauthPluginMeta {

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
