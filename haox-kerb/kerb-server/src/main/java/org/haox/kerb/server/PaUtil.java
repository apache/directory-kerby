package org.haox.kerb.server;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.common.PaDataEntry;
import org.haox.kerb.spec.type.common.PaDataType;

public class PaUtil {
    public static PaDataEntry createPaDataEntry(PaDataType type, byte[] paData) throws KrbException {
        PaDataEntry entry = KrbFactory.create(PaDataEntry.class);
        entry.setPaDataType(type);
        entry.setPaDataValue(paData);
        return entry;
    }
}
