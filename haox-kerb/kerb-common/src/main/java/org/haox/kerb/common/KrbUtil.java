package org.haox.kerb.common;

import org.haox.kerb.crypto2.AbstractEncType;
import org.haox.kerb.crypto2.EncType;
import org.haox.kerb.crypto2.EncTypeMgr;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class KrbUtil {

    public static List<EncryptionType> getEncryptionTypes(List<String> encryptionTypes) {
        if (!encryptionTypes.isEmpty()) {
            List<EncryptionType> results = new ArrayList<EncryptionType>();
            EncryptionType etype;
            for (String etypeName : encryptionTypes) {
                etype = EncryptionType.fromName(etypeName);
                if (etype != EncryptionType.UNKNOWN) {
                    results.add(etype);
                }
            }
            return results;
        }

        return Collections.emptyList();
    }

    public static byte[] encrypt(EncryptionKey key,
          byte[] plaintext, int usage) throws KrbException {
        EncType encType = EncTypeMgr.getEncType(key.getKeyType());
        byte[] cipherData = encType.encrypt(plaintext, key.getKeyData(), usage);
        return cipherData;
    }

    public static byte[] decrypt(EncryptionKey key,
           byte[] cipherData, int usage) throws KrbException {
        EncType encType = EncTypeMgr.getEncType(key.getKeyType());
        byte[] plainData = encType.decrypt(cipherData, key.getKeyData(), usage);
        return plainData;
    }
}
