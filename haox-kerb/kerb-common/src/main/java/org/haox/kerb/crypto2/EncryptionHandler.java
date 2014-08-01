package org.haox.kerb.crypto2;

import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.Config;
import org.haox.kerb.crypto2.enc.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.*;

public class EncryptionHandler {

    private static final boolean ALLOW_WEAK_CRYPTO;

    static {
        boolean allowed = true;
        try {
            Config cfg = Config.getInstance();
            String temp = cfg.getDefault("allow_weak_crypto", "libdefaults");
            if (temp != null && temp.equals("false")) allowed = false;
        } catch (Exception exc) {
            System.out.println ("Exception in getting allow_weak_crypto, " +
                    "using default value " +
                    exc.getMessage());
        }
        ALLOW_WEAK_CRYPTO = allowed;
    }

    public static EncryptionTypeHandler getEncHandler(String eType) throws KrbException {
        EncryptionType eTypeEnum = EncryptionType.fromName(eType);
        return getEncHandler(eTypeEnum);
    }

    public static EncryptionTypeHandler getEncHandler(int eType) throws KrbException {
        EncryptionType eTypeEnum = EncryptionType.fromValue(eType);
        return getEncHandler(eTypeEnum);
    }

    public static EncryptionTypeHandler getEncHandler(EncryptionType eType) throws KrbException {
        EncryptionTypeHandler encType = null;
        switch (eType) {
            case DES_CBC_CRC:
                encType = new DesCbcCrcEnc();
                break;

            case DES_CBC_MD5:
            case DES:
                encType = new DesCbcMd5Enc();
                break;

            case DES3_CBC_SHA1:
            case DES3_CBC_SHA1_KD:
            case DES3_HMAC_SHA1:
                encType = new Des3CbcHmacSha1KdEnc();
                break;

            case AES128_CTS_HMAC_SHA1_96:
            case AES128_CTS:
                encType = new Aes128CtsHmacSha1Enc();
                break;

            case AES256_CTS_HMAC_SHA1_96:
            case AES256_CTS:
                encType = new Aes256CtsHmacSha1Enc();
                break;

            case RC4_HMAC:
            case ARCFOUR_HMAC:
            case ARCFOUR_HMAC_MD5:
                encType = new ArcFourHmacEnc();
                break;

            case NONE:
            default:
                String message = "Unsupported encryption type: " + eType.name();
                throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP, message);
        }

        return encType;
    }

    public static EncryptedData seal(Asn1Type message, EncryptionKey key, KeyUsage usage) throws KrbException {
        byte[] encoded = KrbCodec.encode(message);
        return encrypt(encoded, key, usage);
    }


    public static EncryptedData encrypt(byte[] plainText, EncryptionKey key, KeyUsage usage) throws KrbException {
        EncryptionTypeHandler handler = getEncHandler(key.getKeyType());
        byte[] cipher = handler.encrypt(plainText, key.getKeyData(), usage.getValue());
        EncryptedData ed = new EncryptedData();
        ed.setCipher(cipher);
        ed.setEType(key.getKeyType());
        ed.setKvno(key.getKvno());

        return ed;
    }

    public static byte[] decrypt(EncryptedData data, EncryptionKey key, KeyUsage usage) throws KrbException {
        EncryptionTypeHandler handler = getEncHandler(key.getKeyType());

        byte[] plainData = handler.decrypt(data.getCipher(), key.getKeyData(), usage.getValue());
        return handler.decryptedData(plainData);
    }

    public static EncryptionType[] getSupportedEncTypes() {
        return new EncryptionType[0];
    }

    /*
    public static int[] getDefaults(String configName, EncryptionKey[] keys)
            throws KrbException {
        int[] answer = getDefaults(configName);
        if (answer == null) {
            throw new KrbException("No supported encryption types listed in "
                    + configName);
        }

        List<Integer> list = new ArrayList<Integer>(answer.length);
        for (int i = 0; i < answer.length; i++) {
            if (findKey(answer[i], keys) != null) {
                list.add(answer[i]);
            }
        }
        int len = list.size();
        if (len <= 0) {
            StringBuffer keystr = new StringBuffer();
            for (int i = 0; i < keys.length; i++) {
                keystr.append(toString(keys[i].getKeyType().getValue()));
                keystr.append(" ");
            }
            throw new KrbException(
                    "Do not have keys of types listed in " + configName +
                            " available; only have keys of following type: " +
                            keystr.toString());
        } else {
            answer = new int[len];
            for (int i = 0; i < len; i++) {
                answer[i] = list.get(i);
            }
            return answer;
        }
    }*/

    /*
    public static EncryptionKey findKey(int etype, EncryptionKey[] keys)
            throws KrbException {
        return findKey(etype, null, keys);
    }

    public static EncryptionKey findKey(int etype, Integer kvno, EncryptionKey[] keys)
            throws KrbException {

        // check if encryption type is supported
        if (!EncTypeMgr.isSupported(etype)) {
            throw new KrbException("Encryption type " +
                    EncTypeMgr.toString(etype) + " is not supported/enabled");
        }

        int ktype;
        boolean etypeFound = false;
        for (int i = 0; i < keys.length; i++) {
            ktype = keys[i].getKeyType().getValue();
            if (EncTypeMgr.isSupported(ktype)) {
                Integer kv = keys[i].getKvno();
                if (etype == ktype) {
                    etypeFound = true;
                    if (kvno == kv) {
                        return keys[i];
                    }
                }
            }
        }

        // Key not found.
        // allow DES key to be used for the DES etypes
        if ((etype == DES_CBC_CRC ||
                etype == DES_CBC_MD5)) {
            for (int i = 0; i < keys.length; i++) {
                ktype = keys[i].getKeyType().getValue();
                if (ktype == DES_CBC_CRC ||
                        ktype == DES_CBC_MD5) {
                    Integer kv = keys[i].getKvno();
                    etypeFound = true;
                    if (kvno == kv) {
                        return new EncryptionKey(etype,
                                keys[i].getKeyData());
                    }
                }
            }
        }
        if (etypeFound) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADKEYVER);
        }
        return null;
    }*/

    public static boolean isSupported(EncryptionType eType) {
        EncryptionType[] supportedTypes = getSupportedEncTypes();
        for (int i = 0; i < supportedTypes.length; i++) {
            if (eType == supportedTypes[i]) {
                return true;
            }
        }
        return false;
    }
}
