package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.AbstractUnkeyedCheckSumTypeHandler;
import org.haox.kerb.crypto.cksum.provider.Md4Provider;
import org.haox.kerb.spec.type.common.CheckSumType;

public class RsaMd4CheckSum extends AbstractUnkeyedCheckSumTypeHandler {

    public RsaMd4CheckSum() {
        super(new Md4Provider(), 16, 16);
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD4;
    }
}
