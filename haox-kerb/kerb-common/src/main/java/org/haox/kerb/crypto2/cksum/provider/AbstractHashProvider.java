package org.haox.kerb.crypto2.cksum.provider;

import org.haox.kerb.crypto2.cksum.HashProvider;

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
}
