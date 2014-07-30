package org.haox.kerb.crypto2;

import org.haox.kerb.common.Checksum;
import org.haox.kerb.spec.KrbException;

import java.security.MessageDigest;

public final class RsaMd5CksumType extends CksumType {

    public RsaMd5CksumType() {
    }

    public int confounderSize() {
        return 0;
    }

    public int cksumType() {
        return Checksum.CKSUMTYPE_RSA_MD5;
    }

    public boolean isSafe() {
        return false;
    }

    public int cksumSize() {
        return 16;
    }

    public int keySize() {
        return 0;
    }

    /**
     * Calculates checksum using MD5.
     * @param data the data used to generate the checksum.
     * @param size length of the data.
     * @return the checksum.
     *
     * @modified by Yanni Zhang, 12/08/99.
     */

    public byte[] calculateChecksum(byte[] data, int size) throws KrbException {
        MessageDigest md5;
        byte[] result = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            throw new KrbException("JCE provider may not be installed. " + e.getMessage());
        }
        try {
            md5.update(data);
            result = md5.digest();
        } catch (Exception e) {
            throw new KrbException(e.getMessage());
        }
        return result;
    }

    public byte[] calculateKeyedChecksum(byte[] data, int size,
        byte[] key, int usage) throws KrbException {
                                             return null;
                                         }

    public boolean verifyKeyedChecksum(byte[] data, int size,
        byte[] key, byte[] checksum, int usage) throws KrbException {
        return false;
    }

}
