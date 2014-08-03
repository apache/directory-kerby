package org.haox.kerb.crypto2.enc.provider;

import org.haox.kerb.crypto2.enc.EncryptProvider;

public abstract class AbstractEncryptProvider implements EncryptProvider {
    private int blockSize;
    private int keyInputSize;
    private int keySize;

    public AbstractEncryptProvider(int blockSize, int keyInputSize, int keySize) {
        this.blockSize = blockSize;
        this.keyInputSize = keyInputSize;
        this.keySize = keySize;
    }

    @Override
    public int keyInputSize() {
        return keyInputSize;
    }

    @Override
    public int keySize() {
        return keySize;
    }

    @Override
    public int blockSize() {
        return blockSize;
    }

    @Override
    public void cbcMac(byte[] key, byte[] iv, byte[] data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void cleanState() {

    }

    @Override
    public void cleanKey() {

    }
}
