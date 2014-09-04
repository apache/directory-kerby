package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Des;
import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

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
        return Des.string_to_key_bytes(passwdSalt);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }
}
