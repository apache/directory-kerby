package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.ArcFourHmac;
import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class Rc4KeyMaker extends AbstractKeyMaker {

    public Rc4KeyMaker(EncTypeHandler typeHandler) {
        super(typeHandler);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        try {
            return ArcFourHmac.stringToKey(string.toCharArray());
        } catch (GeneralSecurityException e) {
            throw new KrbException("str2key failed", e);
        }
    }

}
