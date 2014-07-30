package org.haox.kerb.crypto2;

import org.haox.kerb.common.Config;
import org.haox.kerb.common.EncryptedData;
import org.haox.kerb.crypto2.enc.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbErrorCode;

import javax.crypto.Cipher;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public abstract class AbstractEncType implements EncType {

    private static final boolean DEBUG = true;
    private static final boolean ALLOW_WEAK_CRYPTO;

    static {
        boolean allowed = true;
        try {
            Config cfg = Config.getInstance();
            String temp = cfg.getDefault("allow_weak_crypto", "libdefaults");
            if (temp != null && temp.equals("false")) allowed = false;
        } catch (Exception exc) {
            if (DEBUG) {
                System.out.println ("Exception in getting allow_weak_crypto, " +
                                    "using default value " +
                                    exc.getMessage());
            }
        }
        ALLOW_WEAK_CRYPTO = allowed;
    }

    public abstract EncryptionType eType();

    public abstract int minimumPadSize();

    public abstract int confounderSize();

    public abstract int checksumType();

    public abstract int checksumSize();

    public abstract int blockSize();

    public abstract int keySize();

    public abstract byte[] encrypt(byte[] data, byte[] key, int usage)
        throws KrbException;

    public abstract byte[] encrypt(byte[] data, byte[] key, byte[] ivec,
        int usage) throws KrbException;

    public abstract byte[] decrypt(byte[] cipher, byte[] key, int usage)
        throws KrbException;

    public abstract byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec,
        int usage) throws KrbException;

    public int dataSize(byte[] data)
    // throws Asn1Exception
    {
        // EncodeRef ref = new EncodeRef(data, startOfData());
        // return ref.end - startOfData();
        // should be the above according to spec, but in fact
        // implementations include the pad bytes in the data size
        return data.length - startOfData();
    }

    public int padSize(byte[] data) {
        return data.length - confounderSize() - checksumSize() -
            dataSize(data);
    }

    public int startOfChecksum() {
        return confounderSize();
    }

    public int startOfData() {
        return confounderSize() + checksumSize();
    }

    public int startOfPad(byte[] data) {
        return confounderSize() + checksumSize() + dataSize(data);
    }

    public byte[] decryptedData(byte[] data) {
        int tempSize = dataSize(data);
        byte[] result = new byte[tempSize];
        System.arraycopy(data, startOfData(), result, 0, tempSize);
        return result;
    }

    // Note: the first 2 entries of BUILTIN_ETYPES and BUILTIN_ETYPES_NOAES256
    // should be kept DES-related. They will be removed when allow_weak_crypto
    // is set to false.

    private static final int[] BUILTIN_ETYPES = new int[] {
        EncryptedData.ETYPE_AES256_CTS_HMAC_SHA1_96,
        EncryptedData.ETYPE_AES128_CTS_HMAC_SHA1_96,
        EncryptedData.ETYPE_DES3_CBC_HMAC_SHA1_KD,
        EncryptedData.ETYPE_ARCFOUR_HMAC,
        EncryptedData.ETYPE_DES_CBC_CRC,
        EncryptedData.ETYPE_DES_CBC_MD5,
    };

    private static final int[] BUILTIN_ETYPES_NOAES256 = new int[] {
        EncryptedData.ETYPE_AES128_CTS_HMAC_SHA1_96,
        EncryptedData.ETYPE_DES3_CBC_HMAC_SHA1_KD,
        EncryptedData.ETYPE_ARCFOUR_HMAC,
        EncryptedData.ETYPE_DES_CBC_CRC,
        EncryptedData.ETYPE_DES_CBC_MD5,
    };


    // used in Config
    public static int[] getBuiltInDefaults() {
        int allowed = 0;
        try {
            allowed = Cipher.getMaxAllowedKeyLength("AES");
        } catch (Exception e) {
            // should not happen
        }
        int[] result;
        if (allowed < 256) {
            result = BUILTIN_ETYPES_NOAES256;
        } else {
            result = BUILTIN_ETYPES;
        }
        if (!ALLOW_WEAK_CRYPTO) {
            // The last 2 etypes are now weak ones
            return Arrays.copyOfRange(result, 0, result.length - 2);
        }
        return result;
    }

    /**
     * Retrieves the default etypes from the configuration file, or
     * if that's not available, return the built-in list of default etypes.
     */
    // used in KrbAsReq, KeyTab
    public static int[] getDefaults(String configName) {
        try {
            return Config.getInstance().defaultEtype(configName);
        } catch (KrbException exc) {
            if (DEBUG) {
                System.out.println("Exception while getting " +
                    configName + exc.getMessage());
                System.out.println("Using default builtin etypes");
            }
            return getBuiltInDefaults();
        }
    }

    /**
     * Retrieve the default etypes from the configuration file for
     * those etypes for which there are corresponding keys.
     * Used in scenario we have some keys from a keytab with etypes
     * different from those named in configName. Then, in order
     * to decrypt an AS-REP, we should only ask for etypes for which
     * we have keys.
     */
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
    }

    /**
     * Find a key with given etype
     */
    public static EncryptionKey findKey(int etype, EncryptionKey[] keys)
            throws KrbException {
        return findKey(etype, null, keys);
    }

    /**
     * Find a key with given etype and kvno
     * @param kvno if null, return any (first?) key
     */
    public static EncryptionKey findKey(int etype, Integer kvno, EncryptionKey[] keys)
            throws KrbException {

        // check if encryption type is supported
        if (!AbstractEncType.isSupported(etype)) {
            throw new KrbException("Encryption type " +
                    AbstractEncType.toString(etype) + " is not supported/enabled");
        }

        int ktype;
        boolean etypeFound = false;
        for (int i = 0; i < keys.length; i++) {
            ktype = keys[i].getKeyType().getValue();
            if (AbstractEncType.isSupported(ktype)) {
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
        if ((etype == EncryptedData.ETYPE_DES_CBC_CRC ||
                etype == EncryptedData.ETYPE_DES_CBC_MD5)) {
            for (int i = 0; i < keys.length; i++) {
                ktype = keys[i].getKeyType().getValue();
                if (ktype == EncryptedData.ETYPE_DES_CBC_CRC ||
                        ktype == EncryptedData.ETYPE_DES_CBC_MD5) {
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
    }

    public static boolean isSupported(int eTypeConst, int[] config) {
        for (int i = 0; i < config.length; i++) {
            if (eTypeConst == config[i]) {
                return true;
            }
        }
        return false;
    }

    public static boolean isSupported(int eTypeConst) {
        int[] enabledETypes = getBuiltInDefaults();
        return isSupported(eTypeConst, enabledETypes);
    }

    public static String toString(int type) {
        switch (type) {
        case 0:
            return "NULL";
        case 1:
            return "DES CBC mode with CRC-32";
        case 2:
            return "DES CBC mode with MD4";
        case 3:
            return "DES CBC mode with MD5";
        case 4:
            return "reserved";
        case 5:
            return "DES3 CBC mode with MD5";
        case 6:
            return "reserved";
        case 7:
            return "DES3 CBC mode with SHA1";
        case 9:
            return "DSA with SHA1- Cms0ID";
        case 10:
            return "MD5 with RSA encryption - Cms0ID";
        case 11:
            return "SHA1 with RSA encryption - Cms0ID";
        case 12:
            return "RC2 CBC mode with Env0ID";
        case 13:
            return "RSA encryption with Env0ID";
        case 14:
            return "RSAES-0AEP-ENV-0ID";
        case 15:
            return "DES-EDE3-CBC-ENV-0ID";
        case 16:
            return "DES3 CBC mode with SHA1-KD";
        case 17:
            return "AES128 CTS mode with HMAC SHA1-96";
        case 18:
            return "AES256 CTS mode with HMAC SHA1-96";
        case 23:
            return "RC4 with HMAC";
        case 24:
            return "RC4 with HMAC EXP";

        }
        return "Unknown (" + type + ")";
    }
}
