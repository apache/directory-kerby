package org.haox.kerb.crypto2;

import org.haox.kerb.common.Config;
import org.haox.kerb.crypto2.enc.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbErrorCode;

public class EncTypeMgr {

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

    public static EncType getEncType(String eType) throws KrbException {
        EncryptionType eTypeEnum = EncryptionType.fromName(eType);
        return getEncType(eTypeEnum);
    }

    public static EncType getEncType(int eType) throws KrbException {
        EncryptionType eTypeEnum = EncryptionType.fromValue(eType);
        return getEncType(eTypeEnum);
    }

    public static EncType getEncType(EncryptionType eType) throws KrbException {
        EncType encType = null;
        switch (eType) {
            case DES_CBC_CRC:
                encType = new DesCbcCrcEncType();
                break;

            case DES_CBC_MD5:
            case DES:
                encType = new DesCbcMd5EncType();
                break;

            case DES3_CBC_SHA1:
            case DES3_CBC_SHA1_KD:
            case DES3_HMAC_SHA1:
                encType = new Des3CbcHmacSha1KdEncType();
                break;

            case AES128_CTS_HMAC_SHA1_96:
            case AES128_CTS:
                encType = new Aes128CtsHmacSha1EType();
                break;

            case AES256_CTS_HMAC_SHA1_96:
            case AES256_CTS:
                encType = new Aes256CtsHmacSha1EType();
                break;

            case RC4_HMAC:
            case ARCFOUR_HMAC:
            case ARCFOUR_HMAC_MD5:
                encType = new ArcFourHmacEncType();
                break;

            case NULL:
            case UNKNOWN:
                encType = null;
                break;

            default:
                String message = "Unsupported encryption type: " + eType.name();
                throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP, message);
        }

        return encType;
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
