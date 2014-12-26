package org.apache.kerberos.kerb.crypto;

import org.apache.kerberos.kerb.crypto.cksum.HashProvider;
import org.apache.kerberos.kerb.KrbException;

import java.util.Arrays;

/**
 * Based on MIT krb5 hmac.c
 */
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
        byte[] innerPaddedKey = new byte[blockLen];
        byte[] outerPaddedKey = new byte[blockLen];

        // Create the inner padded key
        Arrays.fill(innerPaddedKey, (byte)0x36);
        for (int i = 0; i < key.length; i++) {
            innerPaddedKey[i] ^= key[i];
        }

        // Create the outer padded key
        Arrays.fill(outerPaddedKey, (byte)0x5c);
        for (int i = 0; i < key.length; i++) {
            outerPaddedKey[i] ^= key[i];
        }

        hashProvider.hash(innerPaddedKey);

        hashProvider.hash(data, start, len);

        byte[] tmp = hashProvider.output();

        hashProvider.hash(outerPaddedKey);
        hashProvider.hash(tmp);

        tmp = hashProvider.output();
        return tmp;
    }
}
