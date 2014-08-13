package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.Md5Provider;
import org.haox.kerb.spec.type.common.CheckSumType;

public final class RsaMd5DesCheckSum extends ConfounderedDesCheckSum {

    public RsaMd5DesCheckSum() {
        super(new Md5Provider(), 24, 24);
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD5_DES;
    }
}
