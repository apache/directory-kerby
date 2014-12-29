package org.apache.kerberos.kerb.crypto.key;

import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.crypto.Des;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;

public class DesKeyMaker extends AbstractKeyMaker {

    public DesKeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        String error = null;
        int type = 0;

        if (param != null) {
            if (param.length != 1) {
                error = "Invalid param to S2K";
            }
            type = param[0];
            if (type != 0 && type != 1) {
                error = "Invalid param to S2K";
            }
        }
        if (type == 1) {
            error = "AFS not supported yet";
        }

        if (error != null) {
            throw new KrbException(error);
        }

        char[] passwdSalt = makePasswdSalt(string, salt);
        byte[] key = passwd2key(passwdSalt);
        return key;
    }

    private byte[] passwd2key(char[] passwdSalt) throws KrbException {
        throw new KrbException("Implementation not complete yet");
    }

    /**
     * Note this isn't hit any test yet, and very probably problematic
     */
    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        if (randomBits.length != encProvider().keyInputSize()) {
            throw new KrbException("Invalid random bits, not of correct bytes size");
        }

        /**
         * Ref. k5_rand2key_des in random_to_key.c in MIT krb5
         * Take the seven bytes, move them around into the top 7 bits of the
         * 8 key bytes, then compute the parity bits.  Do this three times.
         */
        byte[] key = new byte[encProvider().keySize()];
        int tmp;
        System.arraycopy(randomBits, 0, key, 0, 7);

        key[7] = (byte) (((key[0] & 1) << 1) |
                ((key[1] & 1) << 2) |
                ((key[2] & 1) << 3) |
                ((key[3] & 1) << 4) |
                ((key[4] & 1) << 5) |
                ((key[5] & 1) << 6) |
                ((key[6] & 1) << 7));

        for (int i = 0; i < 8; i++) {
            tmp = key[i] & 0xfe;
            tmp |= (Integer.bitCount(tmp) & 1) ^ 1;
            key[i] = (byte) tmp;
        }

        Des.fixKey(key, 0, 8);

        return key;
    }

}
