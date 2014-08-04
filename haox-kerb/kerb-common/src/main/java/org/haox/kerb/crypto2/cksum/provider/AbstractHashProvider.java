package org.haox.kerb.crypto2.cksum.provider;

import org.haox.kerb.crypto2.cksum.HashProvider;
import org.haox.kerb.spec.KrbException;

public abstract class AbstractHashProvider implements HashProvider {
    private int blockSize;
    private int hashSize;

    public AbstractHashProvider(int hashSize, int blockSize) {
        this.hashSize = hashSize;
        this.blockSize = blockSize;
    }

    @Override
    public int hashSize() {
        return hashSize;
    }

    @Override
    public int blockSize() {
        return blockSize;
    }

    @Override
    public byte[] hash(byte[] data) throws KrbException {
        return hash(data, 0, data.length);
    }
}
