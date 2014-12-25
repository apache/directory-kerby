package org.haox.kerb.crypto.key;

import org.haox.kerb.KrbException;
import org.haox.kerb.crypto.Nfold;
import org.haox.kerb.crypto.enc.EncryptProvider;

public abstract class DkKeyMaker extends AbstractKeyMaker {

    public DkKeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    // DK(Key, Constant) = random-to-key(DR(Key, Constant))
    public byte[] dk(byte[] key, byte[] constant) throws KrbException {
        return random2Key(dr(key, constant));
    }

    /*
     * K1 = E(Key, n-fold(Constant), initial-cipher-state)
     * K2 = E(Key, K1, initial-cipher-state)
     * K3 = E(Key, K2, initial-cipher-state)
     * K4 = ...
     * DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
     */
    protected byte[] dr(byte[] key, byte[] constant) throws KrbException {

        int blocksize = encProvider().blockSize();
        int keyInuptSize = encProvider().keyInputSize();
        byte[] keyBytes = new byte[keyInuptSize];
        byte[] Ki;

        if (constant.length != blocksize) {
            Ki = Nfold.nfold(constant, blocksize);
        } else {
            Ki = new byte[constant.length];
            System.arraycopy(constant, 0, Ki, 0, constant.length);
        }

        int n = 0, len;
        while (n < keyInuptSize) {
            encProvider().encrypt(key, Ki);

            if (n + blocksize >= keyInuptSize) {
                System.arraycopy(Ki, 0, keyBytes, n, keyInuptSize - n);
                break;
            }

            System.arraycopy(Ki, 0, keyBytes, n, blocksize);
            n += blocksize;
        }

        return keyBytes;
    }
}
