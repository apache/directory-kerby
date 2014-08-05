package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.AbstractCryptoTypeHandler;
import org.haox.kerb.crypto.CheckSumTypeHandler;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractCheckSumTypeHandler
        extends AbstractCryptoTypeHandler implements CheckSumTypeHandler {

    public AbstractCheckSumTypeHandler(EncryptProvider encProvider,
                                       HashProvider hashProvider) {
        super(encProvider, hashProvider);
    }

    @Override
    public String name() {
        return cksumType().getName();
    }

    @Override
    public String displayName() {
        return cksumType().getDisplayName();
    }

    @Override
    public int computeSize() {
        return 0;
    }

    @Override
    public int outputSize() {
        return 0;
    }

    public byte[] calculateChecksum(byte[] data) throws KrbException {
        return calculateChecksum(data, 0, data.length);
    }

    public byte[] calculateChecksum(byte[] data, int start, int size) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public boolean verifyChecksum(byte[] data, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
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
