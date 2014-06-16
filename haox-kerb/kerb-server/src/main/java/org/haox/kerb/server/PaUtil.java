package org.haox.kerb.server;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

public class PaUtil {
    public static PaDataEntry createPaDataEntry(PaDataType type, byte[] paData) throws KrbException {
        PaDataEntry entry = new PaDataEntry();
        entry.setPaDataType(type);
        entry.setPaDataValue(paData);
        return entry;
    }
}
