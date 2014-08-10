package org.haox.kerb.crypto;

import org.haox.kerb.crypto.cksum.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSum;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.common.KrbErrorCode;

public class CheckSumHandler {

    /*
    static int CKSUMTYPE_DEFAULT;
    static int SAFECKSUMTYPE_DEFAULT;

    private static boolean DEBUG = true;
    static {
        String temp = null;
        Config cfg = null;
        try {
            cfg = Config.getInstance();
            temp = cfg.getDefault("default_checksum", "libdefaults");
            if (temp != null)
                {
                    CKSUMTYPE_DEFAULT = cfg.getType(temp);
                } else {
                    CKSUMTYPE_DEFAULT = CKSUMTYPE_RSA_MD5;
                }
        } catch (Exception exc) {
            if (DEBUG) {
                System.out.println("Exception in getting default checksum "+
                                   "value from the configuration " +
                                   "Setting default checksum to be RSA-MD5");
                exc.printStackTrace();
            }
            CKSUMTYPE_DEFAULT = CKSUMTYPE_RSA_MD5;
        }


        try {
            temp = cfg.getDefault("safe_checksum_type", "libdefaults");
            if (temp != null)
                {
                    SAFECKSUMTYPE_DEFAULT = cfg.getType(temp);
                } else {
                    SAFECKSUMTYPE_DEFAULT = CKSUMTYPE_RSA_MD5_DES;
                }
        } catch (Exception exc) {
            if (DEBUG) {
                System.out.println("Exception in getting safe default " +
                                   "checksum value " +
                                   "from the configuration Setting  " +
                                   "safe default checksum to be RSA-MD5");
                exc.printStackTrace();
            }
            SAFECKSUMTYPE_DEFAULT = CKSUMTYPE_RSA_MD5_DES;
        }
    }

     */
    public static CheckSumTypeHandler getCheckSumHandler(String cksumType) throws KrbException {
        CheckSumType eTypeEnum = CheckSumType.fromName(cksumType);
        return getCheckSumHandler(eTypeEnum);
    }

    public static CheckSumTypeHandler getCheckSumHandler(int cksumType) throws KrbException {
        CheckSumType eTypeEnum = CheckSumType.fromValue(cksumType);
        return getCheckSumHandler(eTypeEnum);
    }

    public static boolean isImplemented(CheckSumType cksumType) throws KrbException {
        return getCheckSumHandler(cksumType, true) != null;
    }

    public static CheckSumTypeHandler getCheckSumHandler(CheckSumType cksumType) throws KrbException {
        return getCheckSumHandler(cksumType, false);
    }

    private static CheckSumTypeHandler getCheckSumHandler(CheckSumType cksumType, boolean check) throws KrbException {
        CheckSumTypeHandler cksumHandler = null;
        switch (cksumType) {
            case CRC32:
                cksumHandler = new Crc32CheckSum();
                break;

            case DES_MAC:
                cksumHandler = new DesCbcCheckSum();
                break;

            case RSA_MD4:
                cksumHandler = new RsaMd4CheckSum();
                break;

            case RSA_MD5:
                cksumHandler = new RsaMd5CheckSum();
                break;

            case NIST_SHA:
                cksumHandler = new Sha1CheckSum();
                break;

            case RSA_MD5_DES:
                cksumHandler = new RsaMd5DesCheckSum();
                break;

            case HMAC_SHA1_DES3_KD:
                cksumHandler = new HmacSha1Des3KdCheckSum();
                break;

            case HMAC_SHA1_96_AES128:
                cksumHandler = new HmacSha1Aes128CheckSum();
                break;

            case HMAC_SHA1_96_AES256:
                cksumHandler = new HmacSha1Aes256CheckSum();
                break;

            case HMAC_MD5_ARCFOUR:
                cksumHandler = new HmacMd5Rc4CheckSum();
                break;

            default:
                break;
        }

        if (cksumHandler == null && ! check) {
            String message = "Unsupported checksum type: " + cksumType.name();
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP, message);
        }

        return cksumHandler;
    }

    public static CheckSum checksum(CheckSumType checkSumType, byte[] bytes) throws KrbException {
        CheckSumTypeHandler handler = getCheckSumHandler(checkSumType);
        byte[] checksumBytes = handler.makeChecksum(bytes);
        CheckSum checkSum = new CheckSum();
        checkSum.setCksumtype(checkSumType);
        checkSum.setChecksum(checksumBytes);
        return checkSum;
    }

    public static void verifyChecksum(CheckSum checkSum, byte[] bytes) throws KrbException {
        CheckSumType checkSumType = checkSum.getCksumtype();
        CheckSum newCheckSum = checksum(checkSumType, bytes);

        if (! newCheckSum.equals(checkSum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MODIFIED );
        }
    }

    public static CheckSum checksumWithKey(CheckSumType checkSumType,
                           byte[] bytes, byte[] key, KeyUsage usage) throws KrbException {
        CheckSumTypeHandler handler = getCheckSumHandler(checkSumType);
        byte[] checksumBytes = handler.makeKeyedChecksum(bytes, key, usage.getValue());
        CheckSum checkSum = new CheckSum();
        checkSum.setCksumtype(checkSumType);
        checkSum.setChecksum(checksumBytes);
        return checkSum;
    }

    public static void verifyChecksumWithKey(CheckSum checkSum,
        byte[] bytes, byte[] key, KeyUsage usage) throws KrbException {
        CheckSumType checkSumType = checkSum.getCksumtype();
        CheckSum newCheckSum = checksumWithKey(checkSumType, bytes, key, usage);

        if (! newCheckSum.equals(checkSum)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MODIFIED );
        }
    }
}
