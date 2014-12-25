package org.haox.kerb.crypto;

import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.KrbException;

public class Hmac {

    public static byte[] hmac(HashProvider hashProvider, byte[] key,
                       byte[] data, int outputSize) throws KrbException {
        return hmac(hashProvider, key, data, 0, data.length, outputSize);
    }

    public static byte[] hmac(HashProvider hashProvider, byte[] key, byte[] data,
                       int start, int len, int outputSize) throws KrbException {
        byte[] hash = Hmac.hmac(hashProvider, key, data, start, len);

        byte[] output = new byte[outputSize];
        System.arraycopy(hash, 0, output, 0, outputSize);
        return output;
    }

    public static byte[] hmac(HashProvider hashProvider,
                              byte[] key, byte[] data) throws KrbException {
        return hmac(hashProvider, key, data, 0, data.length);
    }

    public static byte[] hmac(HashProvider hashProvider,
                              byte[] key, byte[] data, int start, int len) throws KrbException {

        int blockLen = hashProvider.blockSize();
        byte[] ipad = new byte[blockLen];
        byte[] opad = new byte[blockLen];

        int ki;
        for (int i = 0; i < blockLen; i++) {
            ki = (i < key.length) ? key[i] : 0;
            ipad[i] = (byte)(ki ^ 0x36);
            opad[i] = (byte)(ki ^ 0x5c);
        }

        hashProvider.hash(ipad);

        hashProvider.hash(data, start, len);

        byte[] tmp = hashProvider.output();

        hashProvider.hash(opad);
        hashProvider.hash(tmp);

        tmp = hashProvider.output();
        return tmp;
    }
}
