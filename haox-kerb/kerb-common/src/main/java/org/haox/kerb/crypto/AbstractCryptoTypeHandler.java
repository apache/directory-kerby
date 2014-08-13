package org.haox.kerb.crypto;

import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.crypto.enc.EncryptProvider;

import java.util.Arrays;

public abstract class AbstractCryptoTypeHandler implements CryptoTypeHandler {

    private EncryptProvider encProvider;
    private HashProvider hashProvider;

    public AbstractCryptoTypeHandler(EncryptProvider encProvider,
                                     HashProvider hashProvider) {
        this.encProvider = encProvider;
        this.hashProvider = hashProvider;
    }

    @Override
    public EncryptProvider encProvider() {
        return encProvider;
    }

    @Override
    public HashProvider hashProvider() {
        return hashProvider;
    }

    protected static boolean checksumEqual(byte[] cksum1, byte[] cksum2) {
        return Arrays.equals(cksum1, cksum2);
    }

    protected static boolean checksumEqual(byte[] cksum1, byte[] cksum2, int cksum2Start, int len) {
        if (cksum1 == cksum2)
            return true;
        if (cksum1 == null || cksum2 == null)
            return false;

        if (len <= cksum2.length && len <= cksum1.length) {
            for (int i = 0; i < len; i++)
                if (cksum1[i] != cksum2[cksum2Start + i])
                    return false;
        } else {
            return false;
        }

        return true;
    }
}
