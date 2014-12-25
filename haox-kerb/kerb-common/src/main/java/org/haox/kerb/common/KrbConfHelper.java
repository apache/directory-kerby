package org.haox.kerb.common;

import org.haox.kerb.spec.common.EncryptionType;

import java.util.ArrayList;
import java.util.List;

public class KrbConfHelper {

    public static List<EncryptionType> getEncryptionTypes(List<String> encTypeNames) {
        List<EncryptionType> results = new ArrayList<EncryptionType>(encTypeNames.size());

        EncryptionType etype;
        for (String etypeName : encTypeNames) {
            etype = EncryptionType.fromName(etypeName);
            if (etype != EncryptionType.NONE) {
                results.add(etype);
            }
        }
        return results;
    }

}
