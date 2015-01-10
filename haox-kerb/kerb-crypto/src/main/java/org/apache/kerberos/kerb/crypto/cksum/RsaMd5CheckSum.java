package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.cksum.provider.AbstractUnkeyedCheckSumTypeHandler;
import org.apache.kerberos.kerb.crypto.cksum.provider.Md5Provider;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class RsaMd5CheckSum extends AbstractUnkeyedCheckSumTypeHandler {

    public RsaMd5CheckSum() {
        super(new Md5Provider(), 16, 16);
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD5;
    }
}
