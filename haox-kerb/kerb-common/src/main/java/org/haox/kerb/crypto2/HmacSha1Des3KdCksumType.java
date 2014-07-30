package org.haox.kerb.crypto2;

import org.haox.kerb.common.Checksum;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class HmacSha1Des3KdCksumType extends CksumType {

    public HmacSha1Des3KdCksumType() {
    }

    public int confounderSize() {
        return 8;
    }

    public int cksumType() {
        return Checksum.CKSUMTYPE_HMAC_SHA1_DES3_KD;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 20;  // bytes
    }

    public int keySize() {
        return 24;   // bytes
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
             return Des3.calculateChecksum(key, usage, data, 0, size);
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
             byte[] newCksum = Des3.calculateChecksum(key, usage,
                 data, 0, size);

             return isChecksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
             KrbException ke = new KrbException(e.getMessage());
             ke.initCause(e);
             throw ke;
         }
     }
}
