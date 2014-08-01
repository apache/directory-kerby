package org.haox.kerb.crypto2.key;

import org.haox.kerb.crypto2.Aes256;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class Aes256KeyMaker extends AbstractKeyMaker {

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        try {
            return Aes256.stringToKey(string.toCharArray(), salt, param);
        } catch (GeneralSecurityException e) {
            throw new KrbException("str2key failed", e);
        }
    }
}
