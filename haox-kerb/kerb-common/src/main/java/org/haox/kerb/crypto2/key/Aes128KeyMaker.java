package org.haox.kerb.crypto2.key;

import org.haox.kerb.crypto2.Aes128;
import org.haox.kerb.crypto2.Des3;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class Aes128KeyMaker extends AbstractKeyMaker {

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        try {
            return Aes128.stringToKey(string.toCharArray(), salt, param);
        } catch (GeneralSecurityException e) {
            throw new KrbException("str2key failed", e);
        }
    }
}
