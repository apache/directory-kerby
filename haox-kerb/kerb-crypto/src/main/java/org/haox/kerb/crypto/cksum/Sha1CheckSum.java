package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.AbstractUnkeyedCheckSumTypeHandler;
import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.spec.common.CheckSumType;

public class Sha1CheckSum extends AbstractUnkeyedCheckSumTypeHandler {

    public Sha1CheckSum() {
        super(new Sha1Provider(), 20, 20);
    }

    public CheckSumType cksumType() {
        return CheckSumType.NIST_SHA;
    }
}
