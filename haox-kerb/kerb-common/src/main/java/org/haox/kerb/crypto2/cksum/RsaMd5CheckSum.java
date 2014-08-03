package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.MessageDigest;

public final class RsaMd5CheckSum extends AbstractCheckSumTypeHandler {

    public RsaMd5CheckSum() {
        super(null, null);
    }

    public int confounderSize() {
        return 0;
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD5;
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

    @Override
    public byte[] calculateChecksum(byte[] data) throws KrbException {
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
}
