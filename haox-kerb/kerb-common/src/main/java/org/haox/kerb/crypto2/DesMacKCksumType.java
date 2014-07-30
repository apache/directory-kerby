package org.haox.kerb.crypto2;

import org.haox.kerb.common.Checksum;
import org.haox.kerb.spec.KrbException;

import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;

public class DesMacKCksumType extends CksumType {

    public DesMacKCksumType() {
    }

    public int confounderSize() {
        return 0;
    }

    public int cksumType() {
        return Checksum.CKSUMTYPE_DES_MAC_K;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 16;
    }

    public int keySize() {
        return 8;
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
     *
     * @modified by Yanni Zhang, 12/08/99.
     */
    public byte[] calculateKeyedChecksum(byte[] data, int size, byte[] key,
        int usage) throws KrbException {
        //check for weak keys
        try {
            if (DESKeySpec.isWeak(key, 0)) {
                key[7] = (byte)(key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        byte[] ivec = new byte[key.length];
        System.arraycopy(key, 0, ivec, 0, key.length);
        byte[] cksum = Des.des_cksum(ivec, data, key);
        return cksum;
    }

    public boolean verifyKeyedChecksum(byte[] data, int size,
        byte[] key, byte[] checksum, int usage) throws KrbException {
        byte[] new_cksum = calculateKeyedChecksum(data, data.length, key, usage);
        return isChecksumEqual(checksum, new_cksum);
    }

}
