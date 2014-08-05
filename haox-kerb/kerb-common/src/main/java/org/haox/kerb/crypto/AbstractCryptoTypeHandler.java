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

    protected static boolean checksumEqual(byte[] origCksum, byte[] newCksum) {
        return Arrays.equals(origCksum, newCksum);
    }

    protected static boolean checksumEqual(byte[] origCksum, byte[] newCksum, int len) {
        if (origCksum == newCksum)
            return true;
        if (origCksum == null || newCksum == null)
            return false;

        if (len <= newCksum.length && len <= origCksum.length) {
            for (int i = 0; i < len; i++)
                if (origCksum[i] != newCksum[i])
                    return false;
        }

        return true;
    }
}
