package org.haox.kerb.crypto.enc.provider;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import java.util.Arrays;

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
    public byte[] initState(byte[] key, int keyUsage) {
        return new byte[0];
    }

    @Override
    public void encrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        doEncrypt(data, key, cipherState, true);
    }

    @Override
    public void decrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        doEncrypt(data, key, cipherState, false);
    }

    @Override
    public void encrypt(byte[] key, byte[] data) throws KrbException {
        byte[] cipherState = new byte[blockSize()];
        encrypt(key, cipherState, data);
    }

    @Override
    public void decrypt(byte[] key, byte[] data) throws KrbException {
        byte[] cipherState = new byte[blockSize()];
        decrypt(key, cipherState, data);
    }

    protected abstract void doEncrypt(byte[] data, byte[] key, byte[] cipherState, boolean encrypt) throws KrbException;

    protected void cbcMac(byte[] key, byte[] iv, byte[] data) {
        throw new UnsupportedOperationException();
    }

    protected boolean supportCbcMac() {
        return false;
    }

    @Override
    public void encryptBlock(byte[] key, byte[] cipherState, byte[] block) throws KrbException {
        if (block.length != blockSize() || blockSize() == 1) {
            throw new KrbException("Invalid block size or not block cipher");
        }

        if (cipherState == null) {
            cipherState = new byte[blockSize()];
            Arrays.fill(cipherState, (byte) 0);
        }
        if (supportCbcMac()) {
            cbcMac(key, cipherState, block);
        } else {
            encrypt(key, cipherState, block);
        }
    }

    @Override
    public void cleanState() {

    }

    @Override
    public void cleanKey() {

    }
}
