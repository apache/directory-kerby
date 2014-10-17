package org.haox.kerb.common;

import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.util.ArrayList;
import java.util.List;

public class EncryptionUtil {

    public static List<EncryptionKey> generateKeys(String principal, String passwd,
                                                   List<EncryptionType> encryptionTypes) throws KrbException {
        List<EncryptionKey> results = new ArrayList<EncryptionKey>(encryptionTypes.size());
        EncryptionKey encKey;
        for (EncryptionType eType : encryptionTypes) {
            encKey = EncryptionHandler.string2Key(principal, passwd, eType);
            results.add(encKey);
        }

        return results;
    }

    public static EncryptionType getBestEncryptionType(List<EncryptionType> requestedTypes,
                                                       List<EncryptionType> configuredTypes) {
        for (EncryptionType encryptionType : configuredTypes) {
            if (requestedTypes.contains(encryptionType)) {
                return encryptionType;
            }
        }

        return null;
    }

    public static byte[] encrypt(EncryptionKey key,
          byte[] plaintext, int usage) throws KrbException {
        EncTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        byte[] cipherData = encType.encrypt(plaintext, key.getKeyData(), usage);
        return cipherData;
    }

    public static byte[] decrypt(EncryptionKey key,
           byte[] cipherData, int usage) throws KrbException {
        EncTypeHandler encType = EncryptionHandler.getEncHandler(key.getKeyType());
        byte[] plainData = encType.decrypt(cipherData, key.getKeyData(), usage);
        return plainData;
    }
}
