package org.haox.kerb.crypto2.enc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.security.MessageDigest;

public final class DesCbcMd5Enc extends DesCbcEnc {

    public DesCbcMd5Enc() {
    }

    public EncryptionType eType() {
        return EncryptionType.DES_CBC_MD5;
    }

    public int minimumPadSize() {
        return 0;
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType checksumType() {
        return CheckSumType.RSA_MD5;
    }

    public int checksumSize() {
        return 16;
    }

    /**
     * Calculates checksum using MD5.
     * @param data the input data.
     * @param size the length of data.
     * @return the checksum.
     *
     * @modified by Yanni Zhang, 12/06/99.
     */
    protected byte[] calculateChecksum(byte[] data, int size)
         throws KrbException {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            throw new KrbException("JCE provider may not be installed. " + e.getMessage());
        }
        try {
            md5.update(data);
            return(md5.digest());
        } catch (Exception e) {
            throw new KrbException(e.getMessage());
        }
    }
}
