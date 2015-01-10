package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.cksum.provider.Md4Provider;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class RsaMd4DesCheckSum extends ConfounderedDesCheckSum {

    public RsaMd4DesCheckSum() {
        super(new Md4Provider(), 24, 24);
    }

    public CheckSumType cksumType() {
        return CheckSumType.RSA_MD4_DES;
    }
}
