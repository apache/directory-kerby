package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Aes256;
import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class Aes256KeyMaker extends AesKeyMaker {

    public Aes256KeyMaker(EncTypeHandler typeHandler) {
        super(typeHandler);
    }

    public byte[] str2keyOld(String string, String salt, byte[] param) throws KrbException {
        try {
            return Aes256.stringToKey(string.toCharArray(), salt, param);
        } catch (GeneralSecurityException e) {
            throw new KrbException("str2key failed", e);
        }
    }
}
