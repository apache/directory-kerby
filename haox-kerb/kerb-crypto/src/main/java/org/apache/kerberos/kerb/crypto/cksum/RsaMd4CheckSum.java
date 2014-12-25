package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.cksum.provider.AbstractUnkeyedCheckSumTypeHandler;
import org.apache.kerberos.kerb.crypto.cksum.provider.Md4Provider;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class RsaMd4CheckSum extends AbstractUnkeyedCheckSumTypeHandler {

    public RsaMd4CheckSum() {
        super(new Md4Provider(), 16, 16);
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD4;
    }
}
