package org.apache.kerberos.kerb.crypto.enc.provider;

import org.apache.kerberos.kerb.crypto.Camellia;
import org.apache.kerberos.kerb.KrbException;

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
    public boolean supportCbcMac() {
        return true;
    }

    @Override
    public byte[] cbcMac(byte[] key, byte[] cipherState, byte[] data) {
        Camellia cipher = new Camellia();
        cipher.setKey(true, key);

        int blocksNum = data.length / blockSize();
        cipher.cbcEnc(data, 0, blocksNum, cipherState);
        return data;
    }
}
