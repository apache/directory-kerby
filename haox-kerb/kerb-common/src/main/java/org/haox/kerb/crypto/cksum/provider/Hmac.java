package org.haox.kerb.crypto.cksum.provider;

import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.spec.KrbException;

public class Hmac {

    public static byte[] hmac(HashProvider hashProvider,
                              byte[] key, byte[] data) throws KrbException {
        return hmac(hashProvider, key, data, 0, data.length);
    }

    public static byte[] hmac(HashProvider hashProvider,
                              byte[] key, byte[] data, int start, int len) throws KrbException {

        int blockLen = hashProvider.blockSize();
        byte[] ipad = new byte[blockLen];
        byte[] opad = new byte[blockLen];

        // XOR k with ipad and opad, respectively
        for (int i = 0; i < blockLen; i++) {
            int si = (i < key.length) ? key[i] : 0;
            ipad[i] = (byte)(si ^ 0x36);
            opad[i] = (byte)(si ^ 0x5c);
        }

        // compute digest for 1st pass; start with inner pad
        hashProvider.hash(ipad);

        // add the selected part of an array of bytes to the inner digest
        hashProvider.hash(data, start, len);

        // finish the inner digest
        byte[] tmp = hashProvider.output();

        // compute digest for 2nd pass; start with outer pad
        hashProvider.hash(opad);
        // add result of 1st hash
        hashProvider.hash(tmp);

        tmp = hashProvider.output();
        return tmp;
    }
}
