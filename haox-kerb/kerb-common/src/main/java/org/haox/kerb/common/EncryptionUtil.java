package org.haox.kerb.common;

import org.haox.asn1.type.AbstractAsn1Type;
import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KeyUsage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class EncryptionUtil {

    public static List<EncryptionKey> generateKeys(List<EncryptionType> encryptionTypes) throws KrbException {
        List<EncryptionKey> results = new ArrayList<EncryptionKey>(encryptionTypes.size());
        EncryptionKey encKey;
        for (EncryptionType eType : encryptionTypes) {
            encKey = EncryptionHandler.random2Key(eType);
            results.add(encKey);
        }

        return results;
    }

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

    public static EncryptedData seal(AbstractAsn1Type asn1Type,
                                     EncryptionKey key, KeyUsage usage) throws KrbException {
        byte[] encoded = asn1Type.encode();
        EncryptedData encrypted = EncryptionHandler.encrypt(encoded, key, usage);
        return encrypted;
    }

    public static AbstractAsn1Type unseal(EncryptedData encrypted, EncryptionKey key,
                                          KeyUsage usage, AbstractAsn1Type container) throws KrbException {
        byte[] encoded = EncryptionHandler.decrypt(encrypted, key, usage);
        try {
            container.decode(encoded);
        } catch (IOException e) {
            throw new KrbException("Failed to decode encTgsRepPart", e);
        }
        return container;
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
