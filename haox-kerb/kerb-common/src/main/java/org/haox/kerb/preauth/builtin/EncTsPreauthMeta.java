package org.haox.kerb.preauth.builtin;

import org.haox.kerb.preauth.PreauthPluginMeta;
import org.haox.kerb.spec.pa.PaDataType;

public class EncTsPreauthMeta implements PreauthPluginMeta {

    private static String NAME = "encrypted_timestamp";
    private static int VERSION = 1;
    private static PaDataType[] PA_TYPES = new PaDataType[] {
            PaDataType.ENC_TIMESTAMP
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
