package org.haox.kerb.common;

import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.crypto.EncryptionTypeHandler;
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
                if (etype != EncryptionType.NONE) {
                    results.add(etype);
                }
            }
            return results;
        }

        return Collections.emptyList();
    }

    public static byte[] encrypt(EncryptionKey key,
          byte[] plaintext, int usage) throws KrbException {
        EncryptionTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        byte[] cipherData = encType.encrypt(plaintext, key.getKeyData(), usage);
        return cipherData;
    }

    public static byte[] decrypt(EncryptionKey key,
           byte[] cipherData, int usage) throws KrbException {
        EncryptionTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        byte[] plainData = encType.decrypt(cipherData, key.getKeyData(), usage);
        return plainData;
    }
}
