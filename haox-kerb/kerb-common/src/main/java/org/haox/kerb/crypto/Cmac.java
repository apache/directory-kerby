package org.haox.kerb.crypto;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

public class Cmac {

    public static byte[] cmac(EncryptProvider encProvider, byte[] key,
                       byte[] data, int outputSize) throws KrbException {
        return cmac(encProvider, key, data, 0, data.length, outputSize);
    }

    public static byte[] cmac(EncryptProvider encProvider, byte[] key, byte[] data,
                       int start, int len, int outputSize) throws KrbException {
        byte[] hash = Cmac.cmac(encProvider, key, data, start, len);

        byte[] output = new byte[outputSize];
        System.arraycopy(hash, 0, output, 0, outputSize);
        return output;
    }

    public static byte[] cmac(EncryptProvider encProvider,
                              byte[] key, byte[] data) throws KrbException {
        return cmac(encProvider, key, data, 0, data.length);
    }

    public static byte[] cmac(EncryptProvider encProvider,
                              byte[] key, byte[] data, int start, int len) throws KrbException {

        int blockLen = encProvider.blockSize();

        byte[] y = new byte[blockLen];
        byte[] mLast = new byte[blockLen];
        byte[] padded = new byte[blockLen];
        byte[] k1 = new byte[blockLen];
        byte[] k2 = new byte[blockLen];

        // step 1
        makeSubkey(encProvider, key, k1, k2);

        // step 2
        int n = (len + blockLen - 1) / len;

        // step 3
        boolean lastIsComplete;
        if (n == 0) {
            n = 1;
            lastIsComplete = false;
        } else {
            lastIsComplete = ((len % blockLen) == 0);
        }

        return null;
        /*
        int ki;
        for (int i = 0; i < blockLen; i++) {
            ki = (i < key.length) ? key[i] : 0;
            ipad[i] = (byte)(ki ^ 0x36);
            opad[i] = (byte)(ki ^ 0x5c);
        }

        encProvider.hash(ipad);

        encProvider.hash(data, start, len);

        byte[] tmp = encProvider.output();

        encProvider.hash(opad);
        encProvider.hash(tmp);

        tmp = encProvider.output();
        return tmp;
        */
    }

    private static void makeSubkey(EncryptProvider encProvider,
                              byte[] key, byte[] k1, byte[] k2) throws KrbException {

    }
}
