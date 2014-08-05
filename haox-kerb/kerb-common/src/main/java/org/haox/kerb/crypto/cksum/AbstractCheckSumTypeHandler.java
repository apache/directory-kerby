package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.AbstractCryptoTypeHandler;
import org.haox.kerb.crypto.CheckSumTypeHandler;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractCheckSumTypeHandler
        extends AbstractCryptoTypeHandler implements CheckSumTypeHandler {

    private int computeSize;
    private int outputSize;

    public AbstractCheckSumTypeHandler(EncryptProvider encProvider, HashProvider hashProvider,
                                       int computeSize, int outputSize) {
        super(encProvider, hashProvider);
        this.computeSize = computeSize;
        this.outputSize = outputSize;
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
        return computeSize;
    }

    @Override
    public int outputSize() {
        return outputSize;
    }

    public byte[] makeChecksum(byte[] data) throws KrbException {
        return makeChecksum(data, 0, data.length);
    }

    public byte[] makeChecksum(byte[] data, int start, int size) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public boolean verifyChecksum(byte[] data, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public byte[] makeKeyedChecksum(byte[] data,
                                    byte[] key, int usage) throws KrbException {
        return makeKeyedChecksum(data, 0, data.length, key, usage);
    }

    public byte[] makeKeyedChecksum(byte[] data, int start, int size,
                                    byte[] key, int usage) throws KrbException {
        throw new UnsupportedOperationException();
    }

    public boolean verifyKeyedChecksum(byte[] data,
                                       byte[] key, int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }
}
