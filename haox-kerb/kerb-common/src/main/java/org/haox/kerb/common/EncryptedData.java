package org.haox.kerb.common;

import org.haox.kerb.crypto2.AbstractEncType;
import org.haox.kerb.crypto2.EncType;
import org.haox.kerb.spec.KrbException;

/**
 * This class encapsulates Kerberos encrypted data. It allows
 * callers access to both the ASN.1 encoded form of the EncryptedData
 * type as well as the raw cipher text.
 */

public class EncryptedData implements Cloneable {
    int eType;
    Integer kvno; // optional
    byte[] cipher;
    byte[] plain; // not part of ASN.1 encoding

    // ----------------+-----------+----------+----------------+---------------
    // Encryption type |etype value|block size|minimum pad size|confounder size
    // ----------------+-----------+----------+----------------+---------------
    public static final int
        ETYPE_NULL        = 0;       // 1          0                0
    public static final int
        ETYPE_DES_CBC_CRC = 1;       // 8          4                8
    public static final int
        ETYPE_DES_CBC_MD4 = 2;       // 8          0                8
    public static final int
        ETYPE_DES_CBC_MD5 = 3;       // 8          0                8

    // draft-brezak-win2k-krb-rc4-hmac-04.txt
    public static final int
        ETYPE_ARCFOUR_HMAC = 23;     // 1
    // NOTE: the exportable RC4-HMAC is not supported;
    // it is no longer a usable encryption type
    public static final int
        ETYPE_ARCFOUR_HMAC_EXP = 24; // 1

     // draft-ietf-krb-wg-crypto-07.txt
    public static final int
        ETYPE_DES3_CBC_HMAC_SHA1_KD = 16; // 8     0                8

    // draft-raeburn-krb-rijndael-krb-07.txt
    public static final int
         ETYPE_AES128_CTS_HMAC_SHA1_96 = 17; // 16      0           16
    public static final int
         ETYPE_AES256_CTS_HMAC_SHA1_96 = 18; // 16      0           16

}
