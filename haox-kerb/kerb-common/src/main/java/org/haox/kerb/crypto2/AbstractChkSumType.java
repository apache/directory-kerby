package org.haox.kerb.crypto2;

import org.haox.kerb.common.Checksum;
import org.haox.kerb.common.Config;
import org.haox.kerb.crypto2.cksum.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbErrorCode;

public abstract class AbstractChkSumType implements ChkSumType {

    private static boolean DEBUG = true;

    public static AbstractChkSumType getInstance(int cksumTypeConst)
        throws KrbException {
        AbstractChkSumType cksumType = null;
        String cksumTypeName = null;
        switch (cksumTypeConst) {
        case Checksum.CKSUMTYPE_CRC32:
            cksumType = new Crc32ChkSumType();
            cksumTypeName = "sun.security.krb5.internal.crypto.Crc32ChkSumType";
            break;
        case Checksum.CKSUMTYPE_DES_MAC:
            cksumType = new DesMacChkSumType();
            cksumTypeName = "sun.security.krb5.internal.crypto.DesMacChkSumType";
            break;
        case Checksum.CKSUMTYPE_DES_MAC_K:
            cksumType = new DesMacKChkSumType();
            cksumTypeName =
                "sun.security.krb5.internal.crypto.DesMacKChkSumType";
            break;
        case Checksum.CKSUMTYPE_RSA_MD5:
            cksumType = new RsaMd5ChkSumType();
            cksumTypeName = "sun.security.krb5.internal.crypto.RsaMd5ChkSumType";
            break;
        case Checksum.CKSUMTYPE_RSA_MD5_DES:
            cksumType = new RsaMd5DesChkSumType();
            cksumTypeName =
                "sun.security.krb5.internal.crypto.RsaMd5DesChkSumType";
            break;

        case Checksum.CKSUMTYPE_HMAC_SHA1_DES3_KD:
            cksumType = new HmacSha1Des3KdChkSumType();
            cksumTypeName =
                "sun.security.krb5.internal.crypto.HmacSha1Des3KdChkSumType";
            break;

        case Checksum.CKSUMTYPE_HMAC_SHA1_96_AES128:
            cksumType = new HmacSha1Aes128ChkSumType();
            cksumTypeName =
                "sun.security.krb5.internal.crypto.HmacSha1Aes128ChkSumType";
            break;
        case Checksum.CKSUMTYPE_HMAC_SHA1_96_AES256:
            cksumType = new HmacSha1Aes256ChkSumType();
            cksumTypeName =
                "sun.security.krb5.internal.crypto.HmacSha1Aes256CksumType";
            break;

        case Checksum.CKSUMTYPE_HMAC_MD5_ARCFOUR:
            cksumType = new HmacMd5ArcFourChkSumType();
            cksumTypeName =
                "sun.security.krb5.internal.crypto.HmacMd5ArcFourChkSumType";
            break;

            // currently we don't support MD4.
        case Checksum.CKSUMTYPE_RSA_MD4_DES_K:
            // cksumType = new RsaMd4DesKCksumType();
            // cksumTypeName =
            //          "sun.security.krb5.internal.crypto.RsaMd4DesKCksumType";
        case Checksum.CKSUMTYPE_RSA_MD4:
            // cksumType = new RsaMd4CksumType();
            // linux box support rsamd4, how to solve conflict?
            // cksumTypeName =
            //          "sun.security.krb5.internal.crypto.RsaMd4CksumType";
        case Checksum.CKSUMTYPE_RSA_MD4_DES:
            // cksumType = new RsaMd4DesCksumType();
            // cksumTypeName =
            //          "sun.security.krb5.internal.crypto.RsaMd4DesCksumType";

        default:
            throw new KrbException(KrbErrorCode.KDC_ERR_SUMTYPE_NOSUPP);
        }
        if (DEBUG) {
            System.out.println(">>> AbstractChkSumType: " + cksumTypeName);
        }
        return cksumType;
    }


    /**
     * Returns default checksum type.
     */
    public static AbstractChkSumType getInstance() throws KrbException {
        // this method provided for Kerberos applications.
        int cksumType = Checksum.CKSUMTYPE_RSA_MD5; // default
        try {
            Config c = Config.getInstance();
            if ((cksumType = (c.getType(c.getDefault("ap_req_checksum_type",
                                "libdefaults")))) == - 1) {
                if ((cksumType = c.getType(c.getDefault("checksum_type",
                                "libdefaults"))) == -1) {
                    cksumType = Checksum.CKSUMTYPE_RSA_MD5; // default
                }
            }
        } catch (KrbException e) {
        }
        return getInstance(cksumType);
    }

    public abstract int confounderSize();

    public abstract int cksumType();

    public abstract boolean isSafe();

    public abstract int cksumSize();

    public abstract int keySize();

    public abstract byte[] calculateChecksum(byte[] data, int size)
        throws KrbException;

    public abstract byte[] calculateKeyedChecksum(byte[] data, int size,
        byte[] key, int usage) throws KrbException;

    public abstract boolean verifyKeyedChecksum(byte[] data, int size,
        byte[] key, byte[] checksum, int usage) throws KrbException;

    public static boolean isChecksumEqual(byte[] cksum1, byte[] cksum2) {
        if (cksum1 == cksum2)
            return true;
        if ((cksum1 == null && cksum2 != null) ||
            (cksum1 != null && cksum2 == null))
            return false;
        if (cksum1.length != cksum2.length)
            return false;
        for (int i = 0; i < cksum1.length; i++)
            if (cksum1[i] != cksum2[i])
                return false;
        return true;
    }

}
