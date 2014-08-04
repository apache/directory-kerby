package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.crypto2.cksum.provider.Md5Provider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.MessageDigest;

public class RsaMd5CheckSum extends AbstractCheckSumTypeHandler {

    public RsaMd5CheckSum() {
        super(null, new Md5Provider());
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
}
