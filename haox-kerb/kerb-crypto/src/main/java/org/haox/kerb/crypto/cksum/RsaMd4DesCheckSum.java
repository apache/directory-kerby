package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.Md4Provider;
import org.haox.kerb.spec.type.common.CheckSumType;

public class RsaMd4DesCheckSum extends ConfounderedDesCheckSum {

    public RsaMd4DesCheckSum() {
        super(new Md4Provider(), 24, 24);
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD4_DES;
    }
}
