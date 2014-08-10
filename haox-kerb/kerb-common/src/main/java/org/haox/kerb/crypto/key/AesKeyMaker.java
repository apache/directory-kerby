package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

public abstract class AesKeyMaker extends AbstractKeyMaker {

    public AesKeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        int iterCount = 4096;
        if (param != null) {
            if (param.length != 4) {
                throw new IllegalArgumentException("Invalid param to str2Key");
            }
            iterCount = readBigEndian(param, 0, 4);
        }

        byte[] saltBytes = null;
        try {
            saltBytes = salt.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        int keySize = encProvider().keySize();
        byte[] random = new byte[0];
        try {
            random = PBKDF2(string.toCharArray(), saltBytes, iterCount, keySize);
        } catch (GeneralSecurityException e) {
            throw new KrbException("PBKDF2 failed", e);
        }

        byte[] tmpKey = random2Key(random);
        byte[] result = dk(tmpKey, KERBEROS_CONSTANT);

        return result;
    }

}
