package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.AbstractUnkeyedCheckSumTypeHandler;
import org.haox.kerb.crypto.cksum.provider.Crc32Provider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

public class Crc32CheckSum extends AbstractUnkeyedCheckSumTypeHandler {

    public Crc32CheckSum() {
        super(new Crc32Provider(), 4, 4);
    }

    public CheckSumType cksumType() {
        return CheckSumType.CRC32;
    }
}
