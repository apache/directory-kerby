package org.haox.kerb.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.util.List;

class KeyImpl {

    private transient byte[] keyBytes;
    private transient int keyType;
    private transient volatile boolean destroyed = false;

    public KeyImpl(byte[] keyBytes,
                       int keyType) {
        this.keyBytes = keyBytes.clone();
        this.keyType = keyType;
    }

    public KeyImpl(PrincipalName principal,
                   char[] password,
                   String algorithm) {

        try {
            PrincipalName princ = principal;
            EncryptionKey key =
                new EncryptionKey(password, getSalt(princ), algorithm);
            this.keyBytes = key.getBytes();
            this.keyType = key.getEType();
        } catch (KrbException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public static String getSalt(PrincipalName principalName) {
        StringBuffer salt = new StringBuffer();
        if (principalName.getRealm() != null) {
            salt.append(principalName.getRealm().toString());
        }
        List<String> nameStrings = principalName.getNameStrings();
        for (String ns : nameStrings) {
            salt.append(ns);
        }
        return salt.toString();
    }

    public final int getKeyType() {
        return keyType;
    }

    public final byte[] getKeyBytes() {
        return keyBytes;
    }

    public final String getAlgorithm() {
        return getAlgorithmName(keyType);
    }

    private String getAlgorithmName(int eType) {
        switch (eType) {
        case EncryptedData.ETYPE_DES_CBC_CRC:
        case EncryptedData.ETYPE_DES_CBC_MD5:
            return "DES";

        case EncryptedData.ETYPE_DES3_CBC_HMAC_SHA1_KD:
            return "DESede";

        case EncryptedData.ETYPE_ARCFOUR_HMAC:
            return "ArcFourHmac";

        case EncryptedData.ETYPE_AES128_CTS_HMAC_SHA1_96:
            return "AES128";

        case EncryptedData.ETYPE_AES256_CTS_HMAC_SHA1_96:
            return "AES256";

        case EncryptedData.ETYPE_NULL:
            return "NULL";

        default:
            throw new IllegalArgumentException(
                "Unsupported encryption type: " + eType);
        }
    }
}
