package org.haox.kerb.crypto2.key;

import org.haox.kerb.spec.KrbException;

public interface KeyMaker {
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException;
}
