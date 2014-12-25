package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.cksum.provider.AbstractUnkeyedCheckSumTypeHandler;
import org.apache.kerberos.kerb.crypto.cksum.provider.Crc32Provider;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class Crc32CheckSum extends AbstractUnkeyedCheckSumTypeHandler {

    public Crc32CheckSum() {
        super(new Crc32Provider(), 4, 4);
    }

    public CheckSumType cksumType() {
        return CheckSumType.CRC32;
    }
}
