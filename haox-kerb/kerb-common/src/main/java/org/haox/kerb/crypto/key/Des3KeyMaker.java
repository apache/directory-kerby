package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Des3;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class Des3KeyMaker extends AbstractKeyMaker {

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        char[] passwdSalt = makePasswdSalt(string, salt);

        try {
            return Des3.stringToKey(passwdSalt);
        } catch (GeneralSecurityException e) {
            throw new KrbException("str2key failed", e);
        }
    }
}
