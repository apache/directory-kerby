package org.haox.kerb.preauth;

import org.haox.kerb.spec.type.pa.PaDataType;

public class TimestampPreauthBase implements Preauth {

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
