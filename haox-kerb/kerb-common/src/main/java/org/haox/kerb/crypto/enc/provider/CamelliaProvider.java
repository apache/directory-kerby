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

        byte[] output = new byte[data.length];
        cipher.processBlock(data, 0, output, 0);
        System.arraycopy(output, 0, data, 0, output.length);
    }
}
