package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.Md5Provider;
import org.haox.kerb.spec.type.common.CheckSumType;

public class RsaMd5CheckSum extends AbstractCheckSumTypeHandler {

    public RsaMd5CheckSum() {
        super(null, new Md5Provider(), 16, 16);
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
