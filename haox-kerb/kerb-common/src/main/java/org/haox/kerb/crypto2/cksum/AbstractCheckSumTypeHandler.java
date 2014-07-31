package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.crypto2.CheckSumTypeHandler;
import org.haox.kerb.spec.KrbException;

import java.util.Arrays;

public abstract class AbstractCheckSumTypeHandler implements CheckSumTypeHandler {

    public byte[] calculateChecksum(byte[] data) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public boolean verifyChecksum(byte[] data, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public byte[] calculateKeyedChecksum(byte[] data,
                                         byte[] key, int usage) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public boolean verifyKeyedChecksum(byte[] data,
                                       byte[] key, int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }

    protected boolean isChecksumEqual(byte[] origCksum, byte[] newCksum) {
        return Arrays.equals(origCksum, newCksum);
    }
}
