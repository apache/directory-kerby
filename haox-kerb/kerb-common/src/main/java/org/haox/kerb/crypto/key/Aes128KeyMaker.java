package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Aes128;
import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class Aes128KeyMaker extends AesKeyMaker {

    public Aes128KeyMaker(EncTypeHandler typeHandler) {
        super(typeHandler);
    }

    public byte[] str2keyOld(String string, String salt, byte[] param) throws KrbException {
        try {
            return Aes128.stringToKey(string.toCharArray(), salt, param);
        } catch (GeneralSecurityException e) {
            throw new KrbException("str2key failed", e);
        }
    }
}
