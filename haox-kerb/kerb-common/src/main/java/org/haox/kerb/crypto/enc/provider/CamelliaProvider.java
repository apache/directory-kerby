package org.haox.kerb.crypto.enc.provider;

import org.haox.kerb.crypto.Camellia;
import org.haox.kerb.spec.KrbException;

public abstract class CamelliaProvider extends AbstractEncryptProvider {

    public CamelliaProvider(int blockSize, int keyInputSize, int keySize) {
        super(blockSize, keyInputSize, keySize);
    }

    @Override
    protected void doEncrypt(byte[] data, byte[] key,
                             byte[] cipherState, boolean encrypt) throws KrbException {

        Camellia cipher = new Camellia();
        cipher.setKey(encrypt, key);
        if (encrypt) {
            cipher.encrypt(data, cipherState);
        } else {
            cipher.decrypt(data, cipherState);
        }
    }

    @Override
    protected boolean supportCbcMac() {
        return true;
    }

    @Override
    protected void cbcMac(byte[] key, byte[] cipherState, byte[] data) {
        Camellia cipher = new Camellia();
        cipher.setKey(true, key);

        int blocksNum = data.length / blockSize();
        cipher.cbcEnc(data, 0, blocksNum, cipherState);
    }
}
