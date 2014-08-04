package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.crypto2.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractKeyedCheckSumTypeHandler extends AbstractCheckSumTypeHandler {

    public AbstractKeyedCheckSumTypeHandler(EncryptProvider encProvider,
                                       HashProvider hashProvider) {
        super(encProvider, hashProvider);
    }

    public byte[] calculateKeyedChecksum(byte[] data,
                                         byte[] key, int usage) throws KrbException {
        return calculateKeyedChecksum(data, 0, data.length, key, usage);
    }

    public byte[] calculateKeyedChecksum(byte[] data, int start, int size,
                                         byte[] key, int usage) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public boolean verifyKeyedChecksum(byte[] data,
                                       byte[] key, int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }
}
