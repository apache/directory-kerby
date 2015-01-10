package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class DesCbcCheckSum extends ConfounderedDesCheckSum {

    public DesCbcCheckSum() {
        super(null, 8, 8);
    }

    public CheckSumType cksumType() {
        return CheckSumType.DES_CBC;
    }
}
