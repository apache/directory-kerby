package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.KrbException;

public abstract class AbstractHashProvider implements HashProvider {
    private int blockSize;
    private int hashSize;

    public AbstractHashProvider(int hashSize, int blockSize) {
        this.hashSize = hashSize;
        this.blockSize = blockSize;
    }

    protected void init() {

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
    public void hash(byte[] data) throws KrbException {
        hash(data, 0, data.length);
    }
}
