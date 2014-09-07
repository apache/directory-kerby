package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Pbkdf;
import org.haox.kerb.crypto.enc.provider.AesProvider;
import org.haox.kerb.spec.KrbException;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

public class AesKeyMaker extends DkKeyMaker {

    public AesKeyMaker(AesProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        int iterCount = getIterCount(param, 4096);

        byte[] saltBytes = null;
        try {
            saltBytes = getSaltBytes(salt, null);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        int keySize = encProvider().keySize();
        byte[] random = new byte[0];
        try {
            random = Pbkdf.PBKDF2(string.toCharArray(), saltBytes, iterCount, keySize);
        } catch (GeneralSecurityException e) {
            throw new KrbException("PBKDF2 failed", e);
        }

        byte[] tmpKey = random2Key(random);
        byte[] result = dk(tmpKey, KERBEROS_CONSTANT);

        return result;
    }

}
