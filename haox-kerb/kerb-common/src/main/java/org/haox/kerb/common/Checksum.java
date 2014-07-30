package org.haox.kerb.common;

import org.haox.kerb.crypto2.AbstractChkSumType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbErrorCode;

public class Checksum {

    private int cksumType;
    private byte[] checksum;

    // ----------------------------------------------+-------------+-----------
    //                      Checksum type            |sumtype      |checksum
    //                                               |value        | size
    // ----------------------------------------------+-------------+-----------
    public static final int CKSUMTYPE_NULL          = 0;               // 0
    public static final int CKSUMTYPE_CRC32         = 1;               // 4
    public static final int CKSUMTYPE_RSA_MD4       = 2;               // 16
    public static final int CKSUMTYPE_RSA_MD4_DES   = 3;               // 24
    public static final int CKSUMTYPE_DES_MAC       = 4;               // 16
    public static final int CKSUMTYPE_DES_MAC_K     = 5;               // 8
    public static final int CKSUMTYPE_RSA_MD4_DES_K = 6;               // 16
    public static final int CKSUMTYPE_RSA_MD5       = 7;               // 16
    public static final int CKSUMTYPE_RSA_MD5_DES   = 8;               // 24

     // draft-ietf-krb-wg-crypto-07.txt
    public static final int CKSUMTYPE_HMAC_SHA1_DES3_KD = 12;          // 20

    // draft-raeburn-krb-rijndael-krb-07.txt
    public static final int CKSUMTYPE_HMAC_SHA1_96_AES128 = 15;        // 96
    public static final int CKSUMTYPE_HMAC_SHA1_96_AES256 = 16;        // 96

    // draft-brezak-win2k-krb-rc4-hmac-04.txt
    public static final int CKSUMTYPE_HMAC_MD5_ARCFOUR = -138;

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
                    /*
                     * If the default checksum is not
                     * specified in the configuration we
                     * set it to RSA_MD5. We follow the MIT and
                     * SEAM implementation.
                     */
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

    /**
     * Constructs a new Checksum using the raw data and type.
     * @data the byte array of checksum.
     * @new_cksumType the type of checksum.
     *
     */
         // used in InitialToken
    public Checksum(byte[] data, int new_cksumType) {
        cksumType = new_cksumType;
        checksum = data;
    }

    /**
     * Constructs a new Checksum by calculating the checksum over the data
     * using specified checksum type.
     * @new_cksumType the type of checksum.
     * @data the data that needs to be performed a checksum calculation on.
     */
    public Checksum(int new_cksumType, byte[] data)
        throws KrbException {

        cksumType = new_cksumType;
        AbstractChkSumType cksumEngine = AbstractChkSumType.getInstance(cksumType);
        if (!cksumEngine.isSafe()) {
            checksum = cksumEngine.calculateChecksum(data, data.length);
        } else {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_INAPP_CKSUM);
        }
    }

    /**
     * Constructs a new Checksum by calculating the keyed checksum
     * over the data using specified checksum type.
     * @new_cksumType the type of checksum.
     * @data the data that needs to be performed a checksum calculation on.
     */
         // KrbSafe, KrbTgsReq
    public Checksum(int new_cksumType, byte[] data,
                        EncryptionKey key, int usage)
        throws KrbException {
        cksumType = new_cksumType;
        AbstractChkSumType cksumEngine = AbstractChkSumType.getInstance(cksumType);
        if (!cksumEngine.isSafe())
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_INAPP_CKSUM);
        checksum =
            cksumEngine.calculateKeyedChecksum(data,
                data.length,
                key.getBytes(),
                usage);
    }

    /**
     * Verifies the keyed checksum over the data passed in.
     */
    public boolean verifyKeyedChecksum(byte[] data, EncryptionKey key,
                                        int usage)
        throws KrbException {
        AbstractChkSumType cksumEngine = AbstractChkSumType.getInstance(cksumType);
        if (!cksumEngine.isSafe())
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_INAPP_CKSUM);
        return cksumEngine.verifyKeyedChecksum(data,
                                               data.length,
                                               key.getBytes(),
                                               checksum,
            usage);
    }

    /*
    public Checksum(byte[] data) throws KdcErrException, KrbCryptoException {
        this(Checksum.CKSUMTYPE_DEFAULT, data);
    }
    */

    boolean isEqual(Checksum cksum) throws KrbException {
        if (cksumType != cksum.cksumType)
            return false;
        AbstractChkSumType cksumEngine = AbstractChkSumType.getInstance(cksumType);
        return cksumEngine.isChecksumEqual(checksum, cksum.checksum);
    }


    /**
     * Returns the raw bytes of the checksum, not in ASN.1 encoded form.
     */
    public final byte[] getBytes() {
        return checksum;
    }

    public final int getType() {
        return cksumType;
    }
}
