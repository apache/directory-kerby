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
        char[] passwdSalt = makePasswdSalt(string, salt);

        return Des.string_to_key_bytes(passwdSalt);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }
}
