package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.cksum.provider.Crc32Provider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

public class Crc32CheckSum extends AbstractCheckSumTypeHandler {

    public Crc32CheckSum() {
        super(null, new Crc32Provider(), 4, 4);
    }

    public int confounderSize() {
        return 0;
    }

    public CheckSumType cksumType() {
        return CheckSumType.CRC32;
    }

    public boolean isSafe() {
        return false;
    }

    public int cksumSize() {
        return 4;
    }

    public int keySize() {
        return 0;
    }

    @Override
    public byte[] makeChecksum(byte[] data, int start, int size) throws KrbException {
        hashProvider().hash(data, start, size);
        return hashProvider().output();
    }
}
