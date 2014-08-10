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

    public boolean isSafe() {
        return false;
    }

    public int cksumSize() {
        return 4;
    }

    public int keySize() {
        return 0;
    }

    public int confounderSize() {
        return 0;
    }

    @Override
    public byte[] makeChecksum(byte[] data) throws KrbException {
        return makeChecksum(data, 0, data.length);
    }

    @Override
    public byte[] makeChecksum(byte[] data, int start, int size) throws KrbException {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean verifyChecksum(byte[] data, byte[] checksum) throws KrbException {
        return verifyChecksum(data, 0, data.length, checksum);
    }

    @Override
    public boolean verifyChecksum(byte[] data, int start, int size, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] makeKeyedChecksum(byte[] data,
                                    byte[] key, int usage) throws KrbException {
        return makeKeyedChecksum(data, 0, data.length, key, usage);
    }

    @Override
    public byte[] makeKeyedChecksum(byte[] data, int start, int size,
                                    byte[] key, int usage) throws KrbException {
        throw new UnsupportedOperationException();
    }
    @Override
    public boolean verifyKeyedChecksum(byte[] data,
                                       byte[] key, int usage, byte[] checksum) throws KrbException {
        throw new UnsupportedOperationException();
    }
}
