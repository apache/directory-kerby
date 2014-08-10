package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.AbstractUnkeyedCheckSumTypeHandler;
import org.haox.kerb.crypto.cksum.provider.Md5Provider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

public class RsaMd5CheckSum extends AbstractUnkeyedCheckSumTypeHandler {

    public RsaMd5CheckSum() {
        super(new Md5Provider(), 16, 16);
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD5;
    }
}
