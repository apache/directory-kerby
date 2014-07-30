package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.common.Checksum;
import org.haox.kerb.crypto2.AbstractChkSumType;
import org.haox.kerb.crypto2.Aes256;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class HmacSha1Aes256ChkSumType extends AbstractChkSumType {

    public HmacSha1Aes256ChkSumType() {
    }

    public int confounderSize() {
        return 16;
    }

    public int cksumType() {
        return Checksum.CKSUMTYPE_HMAC_SHA1_96_AES256;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 12;  // bytes
    }

    public int keySize() {
        return 32;   // bytes
    }

    public byte[] calculateChecksum(byte[] data, int size) {
        return null;
    }

    /**
     * Calculates keyed checksum.
     * @param data the data used to generate the checksum.
     * @param size length of the data.
     * @param key the key used to encrypt the checksum.
     * @return keyed checksum.
     */
    public byte[] calculateKeyedChecksum(byte[] data, int size, byte[] key,
        int usage) throws KrbException {

         try {
            return sun.security.krb5.internal.crypto.Aes256.calculateChecksum(key, usage, data, 0, size);
         } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
         }
    }

    /**
     * Verifies keyed checksum.
     * @param data the data.
     * @param size the length of data.
     * @param key the key used to encrypt the checksum.
     * @param checksum
     * @return true if verification is successful.
     */
    public boolean verifyKeyedChecksum(byte[] data, int size,
        byte[] key, byte[] checksum, int usage) throws KrbException {

         try {
            byte[] newCksum = Aes256.calculateChecksum(key, usage, data,
                    0, size);
            return isChecksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
         }
    }
}
