package org.apache.kerberos.kerb.crypto.key;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.crypto.Des;
import org.apache.kerberos.kerb.crypto.Nfold;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;

import java.io.UnsupportedEncodingException;

public class Des3KeyMaker extends DkKeyMaker {

    public Des3KeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        char[] passwdSalt = makePasswdSalt(string, salt);
        int keyInputSize = encProvider().keyInputSize();
        try {
            byte[] utf8Bytes = new String(passwdSalt).getBytes("UTF-8");
            byte[] tmpKey = random2Key(Nfold.nfold(utf8Bytes, keyInputSize));
            return dk(tmpKey, KERBEROS_CONSTANT);
        } catch (UnsupportedEncodingException e) {
            throw new KrbException("str2key failed", e);
        }
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        /**
         * Ref. k5_rand2key_des3 in random_to_key.c
         * Take the seven bytes, move them around into the top 7 bits of the
         * 8 key bytes, then compute the parity bits.  Do this three times.
         */
        byte[] key = new byte[24];
        int nthByte;
        int tmp;
        for (int i = 0; i < 3; i++) {
            System.arraycopy(randomBits, i * 7, key, i * 8, 7);
            nthByte = i * 8;

            key[nthByte + 7] = (byte) (((key[nthByte + 0] & 1) << 1) |
                    ((key[nthByte + 1] & 1) << 2) |
                    ((key[nthByte + 2] & 1) << 3) |
                    ((key[nthByte + 3] & 1) << 4) |
                    ((key[nthByte + 4] & 1) << 5) |
                    ((key[nthByte + 5] & 1) << 6) |
                    ((key[nthByte + 6] & 1) << 7));

            for (int j = 0; j < 8; j++) {
                tmp = key[nthByte + j] & 0xfe;
                tmp |= (Integer.bitCount(tmp) & 1) ^ 1;
                key[nthByte + j] = (byte) tmp;
            }
        }

        for (int i = 0; i < 3; i++) {
            Des.fixKey(key, i * 8, 8);
        }

        return key;
    }
}
