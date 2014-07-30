package org.haox.kerb.common;

import org.haox.kerb.crypto2.EType;
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

    private EncryptedData() {
    }

    public EncryptedData(
                         int new_eType,
                         Integer new_kvno,
                         byte[] new_cipher) {
        eType = new_eType;
        kvno = new_kvno;
        cipher = new_cipher;
    }

    public EncryptedData(
                         EncryptionKey key,
                         byte[] plaintext,
                         int usage)
        throws KrbException {
        EType etypeEngine = EType.getInstance(key.getEType());
        cipher = etypeEngine.encrypt(plaintext, key.getBytes(), usage);
        eType = key.getEType();
        kvno = key.getKeyVersionNumber();
    }

    // currently destructive on cipher
    public byte[] decrypt(
                          EncryptionKey key, int usage)
        throws KrbException {
            if (eType != key.getEType()) {
                throw new KrbException(
                    "EncryptedData is encrypted using keytype " +
                    EType.toString(eType) +
                    " but decryption key is of type " +
                    EType.toString(key.getEType()));
            }

            EType etypeEngine = EType.getInstance(eType);
            plain = etypeEngine.decrypt(cipher, key.getBytes(), usage);
            cipher = null;
            return etypeEngine.decryptedData(plain);
        }

    private byte[] decryptedData() throws KrbException {
        if (plain != null) {
            EType etypeEngine = EType.getInstance(eType);
            return etypeEngine.decryptedData(plain);
        }
        return null;
    }

    /**
     * Reset asn.1 data stream after decryption, remove redundant bytes.
     * @param data the decrypted data from decrypt().
     * @return the reset byte array which holds exactly one asn1 datum
     * including its tag and length.
     *
     */
    public byte[] reset(byte[] data) {
        byte[]  bytes = null;
        // for asn.1 encoded data, we use length field to
        // determine the data length and remove redundant paddings.
        if ((data[1] & 0xFF) < 128) {
            bytes = new byte[data[1] + 2];
            System.arraycopy(data, 0, bytes, 0, data[1] + 2);
        } else {
            if ((data[1] & 0xFF) > 128) {
                int len = data[1] & (byte)0x7F;
                int result = 0;
                for (int i = 0; i < len; i++) {
                    result |= (data[i + 2] & 0xFF) << (8 * (len - i - 1));
                }
                bytes = new byte[result + len + 2];
                System.arraycopy(data, 0, bytes, 0, result + len + 2);
            }
        }
        return bytes;
    }

    public int getEType() {
        return eType;
    }

    public Integer getKeyVersionNumber() {
        return kvno;
    }

    /**
     * Returns the raw cipher text bytes, not in ASN.1 encoding.
     */
    public byte[] getBytes() {
        return cipher;
    }
}
